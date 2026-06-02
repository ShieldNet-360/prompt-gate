package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// helperServer spins up an httptest.Server that serves
//   - /manifest.json  → the given manifest body
//   - /binary         → the given binary body
//
// The returned closeFunc tears the server down.
func helperServer(t *testing.T, manifest Manifest, binary []byte) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(manifest)
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binary)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckLatest_ReportsUpdateAvailable(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := helperServer(t, Manifest{
		Version: "0.2.0",
		Channels: map[string]ManifestEntry{
			runtime.GOOS + "/" + runtime.GOARCH: {
				URL:       "http://example.test/binary",
				SHA256Hex: strings.Repeat("a", 64),
				SigHex:    strings.Repeat("b", 128),
			},
		},
	}, nil)
	u, err := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		Current:     "0.1.0",
		PublicKey:   pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := u.CheckLatest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.UpdateAvailable {
		t.Fatalf("expected update_available=true, got %+v", res)
	}
	if res.Latest != "0.2.0" {
		t.Fatalf("latest = %q", res.Latest)
	}
}

func TestCheckLatest_NoUpdateWhenSameVersion(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := helperServer(t, Manifest{
		Version: "0.1.0",
		Channels: map[string]ManifestEntry{
			platformKey(): {URL: "x", SHA256Hex: "y", SigHex: "z"},
		},
	}, nil)
	u, _ := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		Current:     "0.1.0",
		PublicKey:   pub,
	})
	res, err := u.CheckLatest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.UpdateAvailable {
		t.Fatalf("did not expect update_available=true")
	}
}

func TestDownloadAndStage_VerifiesShaAndSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	bin := []byte("imagine this is the agent binary contents v0.2.0")
	digest := sha256.Sum256(bin)
	sig := ed25519.Sign(priv, digest[:])

	mux := http.NewServeMux()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Manifest{
			Version: "0.2.0",
			Channels: map[string]ManifestEntry{
				platformKey(): {
					URL:       "{{HOST}}/binary",
					SHA256Hex: hex.EncodeToString(digest[:]),
					SigHex:    hex.EncodeToString(sig),
				},
			},
		})
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bin)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	// Rewrite the manifest URL placeholder to point at the test server.
	rewrite := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/manifest.json" {
			_ = json.NewEncoder(w).Encode(Manifest{
				Version: "0.2.0",
				Channels: map[string]ManifestEntry{
					platformKey(): {
						URL:       srv.URL + "/binary",
						SHA256Hex: hex.EncodeToString(digest[:]),
						SigHex:    hex.EncodeToString(sig),
					},
				},
			})
			return
		}
		_, _ = w.Write(bin)
	})
	mfx := httptest.NewServer(rewrite)
	defer mfx.Close()

	stage := t.TempDir()
	u, _ := New(Options{
		ManifestURL: mfx.URL + "/manifest.json",
		Current:     "0.1.0",
		PublicKey:   pub,
		StageDir:    stage,
	})
	res, err := u.DownloadAndStage(context.Background())
	if err != nil {
		t.Fatalf("download+stage: %v", err)
	}
	if res.Version != "0.2.0" {
		t.Fatalf("version = %q", res.Version)
	}
	staged := filepath.Join(stage, "agent-0.2.0")
	if _, err := os.Stat(staged); err != nil {
		t.Fatalf("staged binary missing: %v", err)
	}
}

func TestDownloadAndStage_RejectsBadSha(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	bin := []byte("a binary")
	correctDigest := sha256.Sum256(bin)
	sig := ed25519.Sign(priv, correctDigest[:])

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		// SHA256 deliberately wrong (all zeros), signature legitimate.
		_ = json.NewEncoder(w).Encode(Manifest{
			Version: "0.2.0",
			Channels: map[string]ManifestEntry{
				platformKey(): {
					URL:       srv.URL + "/binary",
					SHA256Hex: strings.Repeat("0", 64),
					SigHex:    hex.EncodeToString(sig),
				},
			},
		})
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bin) })

	u, _ := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		Current:     "0.1.0",
		PublicKey:   pub,
		StageDir:    t.TempDir(),
	})
	if _, err := u.DownloadAndStage(context.Background()); err == nil {
		t.Fatal("expected sha256 mismatch error")
	}
}

func TestDownloadAndStage_RejectsPathTraversalVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	bin := []byte("imagine this is the agent binary contents")
	digest := sha256.Sum256(bin)
	sig := ed25519.Sign(priv, digest[:])

	// Each entry: a hostile version string that must be rejected before
	// any file is written to the stage directory.
	hostileVersions := []string{
		"../../../tmp/pwned",
		"..",
		"./escape",
		"-rf",
		"v1.0/../../etc/passwd",
		"v1.0\\..\\..\\windows",
		"v1.0\x00.bin",
		"v1.0;rm -rf",
		strings.Repeat("a", 65),
	}

	for _, v := range hostileVersions {
		v := v
		t.Run("hostile_"+v, func(t *testing.T) {
			mux := http.NewServeMux()
			srv := httptest.NewServer(mux)
			defer srv.Close()
			mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(Manifest{
					Version: v,
					Channels: map[string]ManifestEntry{
						platformKey(): {
							URL:       srv.URL + "/binary",
							SHA256Hex: hex.EncodeToString(digest[:]),
							SigHex:    hex.EncodeToString(sig),
						},
					},
				})
			})
			mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(bin)
			})

			stage := t.TempDir()
			u, _ := New(Options{
				ManifestURL: srv.URL + "/manifest.json",
				Current:     "0.1.0",
				PublicKey:   pub,
				StageDir:    stage,
			})
			if _, err := u.DownloadAndStage(context.Background()); err == nil {
				t.Fatalf("expected error for hostile version %q", v)
			}
			// Verify no file was written anywhere under the stage dir.
			entries, err := os.ReadDir(stage)
			if err == nil && len(entries) > 0 {
				t.Fatalf("expected empty stage dir for hostile version %q, got %d entries", v, len(entries))
			}
			// Also verify the CheckLatest path rejects the same manifest.
			if _, err := u.CheckLatest(context.Background()); err == nil {
				t.Fatalf("expected CheckLatest to reject hostile version %q", v)
			}
		})
	}
}

func TestValidateVersion_AcceptsValidStrings(t *testing.T) {
	for _, v := range []string{
		"0.1.0",
		"1.2.3",
		"1.2.3-beta",
		"1.2.3+sha.deadbeef",
		"v1.0.0",
		"2024.01.15",
	} {
		if err := validateVersion(v); err != nil {
			t.Errorf("validateVersion(%q) unexpected error: %v", v, err)
		}
	}
}

func TestDownloadAndStage_RejectsBadSignature(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	otherPub, otherPriv, _ := ed25519.GenerateKey(nil)
	_ = otherPub
	bin := []byte("binary again")
	digest := sha256.Sum256(bin)
	// Sign with a different private key than the verifier's public key.
	wrongSig := ed25519.Sign(otherPriv, digest[:])

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/manifest.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(Manifest{
			Version: "0.2.0",
			Channels: map[string]ManifestEntry{
				platformKey(): {
					URL:       srv.URL + "/binary",
					SHA256Hex: hex.EncodeToString(digest[:]),
					SigHex:    hex.EncodeToString(wrongSig),
				},
			},
		})
	})
	mux.HandleFunc("/binary", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(bin) })

	u, _ := New(Options{
		ManifestURL: srv.URL + "/manifest.json",
		Current:     "0.1.0",
		PublicKey:   pub,
		StageDir:    t.TempDir(),
	})
	if _, err := u.DownloadAndStage(context.Background()); err == nil {
		t.Fatal("expected signature verification failure")
	}
}
