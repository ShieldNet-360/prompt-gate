// Package updater implements agent self-update against a manifest
// hosted on GitHub Releases (Phase 6 Task 15).
//
// The updater is intentionally minimal:
//
//   1. CheckLatest() fetches a JSON manifest at ManifestURL and
//      returns (latest version string, download URL, expected SHA256,
//      expected Ed25519 signature) for the running platform.
//   2. DownloadAndStage(latest) downloads the binary into Dir, verifies
//      the SHA256 and Ed25519 signature against PublicKey, and stages
//      the new binary alongside the current one. The actual swap is
//      left to a thin platform-specific bootstrapper invoked at
//      restart — the updater never modifies a running binary.
//
// Privacy invariant: the updater speaks only to the configured
// ManifestURL host (default github.com / api.github.com). No telemetry
// is sent and no user data is included in any request.
package updater

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// CheckResult is the outcome of a manifest poll.
type CheckResult struct {
	Latest        string `json:"latest"`
	Current       string `json:"current"`
	UpdateAvailable bool `json:"update_available"`
	DownloadURL   string `json:"download_url,omitempty"`
}

// StageResult is the outcome of a download+verify cycle.
type StageResult struct {
	Version   string `json:"version"`
	StagedAt  string `json:"staged_at"`
	BytesSize int64  `json:"bytes_size"`
}

// Manifest is the JSON shape served at ManifestURL.
type Manifest struct {
	Version  string                   `json:"version"`
	Channels map[string]ManifestEntry `json:"channels"`
}

// ManifestEntry holds per-platform metadata for one release.
type ManifestEntry struct {
	URL       string `json:"url"`
	SHA256Hex string `json:"sha256"`
	SigHex    string `json:"signature"`
}

// Options configures a Self-updater.
type Options struct {
	// ManifestURL is the HTTPS URL of the release manifest. Required.
	ManifestURL string

	// Current is the version of the running agent (e.g. "0.1.0").
	Current string

	// StageDir is the directory where verified binaries are staged.
	// Defaults to <executable-dir>/.staged when empty.
	StageDir string

	// PublicKey is the Ed25519 public key used to verify release
	// signatures. Required.
	PublicKey ed25519.PublicKey

	// Client is the HTTP client used for both manifest and binary
	// downloads. Defaults to a 30-second-timeout client.
	Client *http.Client
}

// Self represents the self-updater. Construct via New.
type Self struct {
	opts Options
}

// New returns a configured Self. Returns an error when required
// options are missing.
func New(opts Options) (*Self, error) {
	if opts.ManifestURL == "" {
		return nil, errors.New("updater: ManifestURL required")
	}
	if len(opts.PublicKey) == 0 {
		return nil, errors.New("updater: PublicKey required")
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Self{opts: opts}, nil
}

// CheckLatest fetches the manifest and returns the latest version
// metadata for the running platform. Returns an error when the
// manifest is unreachable, malformed, or omits the running platform.
func (s *Self) CheckLatest(ctx context.Context) (CheckResult, error) {
	manifest, _, err := s.fetchManifest(ctx)
	if err != nil {
		return CheckResult{}, err
	}
	entry, ok := manifest.Channels[platformKey()]
	if !ok {
		return CheckResult{}, fmt.Errorf("updater: manifest has no entry for %s", platformKey())
	}
	res := CheckResult{
		Latest:          manifest.Version,
		Current:         s.opts.Current,
		UpdateAvailable: manifest.Version != s.opts.Current,
		DownloadURL:     entry.URL,
	}
	return res, nil
}

// DownloadAndStage downloads the latest release for this platform,
// verifies the SHA256 and Ed25519 signature, and writes the binary to
// the stage directory. Returns metadata describing the staged file.
func (s *Self) DownloadAndStage(ctx context.Context) (StageResult, error) {
	manifest, _, err := s.fetchManifest(ctx)
	if err != nil {
		return StageResult{}, err
	}
	entry, ok := manifest.Channels[platformKey()]
	if !ok {
		return StageResult{}, fmt.Errorf("updater: manifest has no entry for %s", platformKey())
	}
	if entry.SHA256Hex == "" || entry.SigHex == "" {
		return StageResult{}, errors.New("updater: manifest entry missing sha256 or signature")
	}

	body, err := s.fetch(ctx, entry.URL)
	if err != nil {
		return StageResult{}, fmt.Errorf("updater: download: %w", err)
	}

	digest := sha256.Sum256(body)
	gotDigest := hex.EncodeToString(digest[:])
	if !strings.EqualFold(gotDigest, entry.SHA256Hex) {
		return StageResult{}, fmt.Errorf("updater: sha256 mismatch (got %s, want %s)", gotDigest, entry.SHA256Hex)
	}

	sig, err := hex.DecodeString(entry.SigHex)
	if err != nil {
		return StageResult{}, fmt.Errorf("updater: invalid signature encoding: %w", err)
	}
	if !ed25519.Verify(s.opts.PublicKey, digest[:], sig) {
		return StageResult{}, errors.New("updater: signature verification failed")
	}

	if err := validateVersion(manifest.Version); err != nil {
		return StageResult{}, err
	}
	stageDir, err := s.stageDir()
	if err != nil {
		return StageResult{}, err
	}
	if err := os.MkdirAll(stageDir, 0o755); err != nil {
		return StageResult{}, fmt.Errorf("updater: mkdir stage dir: %w", err)
	}
	// Defence in depth: even though validateVersion rejects path
	// separators, recompute the absolute path and confirm it lives
	// inside stageDir before writing.
	absStage, err := filepath.Abs(stageDir)
	if err != nil {
		return StageResult{}, fmt.Errorf("updater: resolve stage dir: %w", err)
	}
	path := filepath.Join(absStage, "agent-"+manifest.Version)
	absPath, err := filepath.Abs(path)
	if err != nil {
		return StageResult{}, fmt.Errorf("updater: resolve staged path: %w", err)
	}
	if rel, err := filepath.Rel(absStage, absPath); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.Contains(rel, string(filepath.Separator)) {
		return StageResult{}, fmt.Errorf("updater: staged path escapes stage dir: %s", path)
	}
	if err := os.WriteFile(absPath, body, 0o755); err != nil {
		return StageResult{}, fmt.Errorf("updater: write staged binary: %w", err)
	}
	path = absPath
	return StageResult{
		Version:   manifest.Version,
		StagedAt:  path,
		BytesSize: int64(len(body)),
	}, nil
}

func (s *Self) fetchManifest(ctx context.Context) (Manifest, []byte, error) {
	body, err := s.fetch(ctx, s.opts.ManifestURL)
	if err != nil {
		return Manifest{}, nil, fmt.Errorf("updater: manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		return Manifest{}, nil, fmt.Errorf("updater: parse manifest: %w", err)
	}
	if err := validateVersion(m.Version); err != nil {
		return Manifest{}, nil, err
	}
	return m, body, nil
}

func (s *Self) fetch(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.opts.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	// 100 MiB cap is generous for an agent binary and protects against
	// a hostile manifest pointing at /dev/zero.
	return io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024))
}

func (s *Self) stageDir() (string, error) {
	if s.opts.StageDir != "" {
		return s.opts.StageDir, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("updater: locate executable: %w", err)
	}
	return filepath.Join(filepath.Dir(exe), ".staged"), nil
}

func platformKey() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// validateVersion rejects manifest version strings that could escape
// the stage directory or otherwise be used to write outside it. The
// allowed alphabet is a conservative superset of SemVer: ASCII
// alphanumerics plus '.', '+', '_', '-'. Leading '.' or '-' are
// rejected to prevent dotfile or option-injection style names.
func validateVersion(v string) error {
	if v == "" {
		return errors.New("updater: manifest version is empty")
	}
	if len(v) > 64 {
		return fmt.Errorf("updater: manifest version too long (%d > 64)", len(v))
	}
	if v == ".." || strings.Contains(v, "/") || strings.Contains(v, "\\") || strings.Contains(v, "..") {
		return fmt.Errorf("updater: manifest version contains path traversal: %q", v)
	}
	if v[0] == '.' || v[0] == '-' {
		return fmt.Errorf("updater: manifest version has illegal leading character: %q", v)
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '.' || r == '+' || r == '_' || r == '-':
		default:
			return fmt.Errorf("updater: manifest version contains illegal character %q in %q", r, v)
		}
	}
	return nil
}
