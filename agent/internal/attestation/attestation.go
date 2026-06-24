// Package attestation produces a signed, offline-verifiable statement
// about what Prompt Gate build is running on a machine and how it is
// configured. Cloud-routed DLP tools cannot offer this — on-device
// attestation is structurally unique to a local agent.
//
// A per-install Ed25519 key is generated on first use and stored at
// <dir>/attestation.key (0600). The agent signs a small JSON payload
// (version, OS, rule-bundle hash, tamper status, anonymous counters);
// an auditor verifies the signature offline with the embedded public
// key. The payload contains NO scanned content, URLs, or hostnames.
package attestation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// KeyFileName is the per-install private key file inside the data dir.
const KeyFileName = "attestation.key"

// Payload is the attested statement. Field order is fixed so that
// encoding/json produces deterministic bytes (Ed25519 signs raw bytes).
// Every field is non-sensitive: no content, URLs, or hostnames.
type Payload struct {
	AgentVersion    string `json:"agent_version"`
	OSType          string `json:"os_type"`
	OSArch          string `json:"os_arch"`
	ExportedAtUnix  int64  `json:"exported_at_unix"`
	DLPPatternCount int    `json:"dlp_pattern_count"`
	DLPRulesSHA256  string `json:"dlp_rules_sha256"`
	ScansTotal      uint64 `json:"scans_total"`
	BlocksTotal     uint64 `json:"blocks_total"`
	TamperOK        bool   `json:"tamper_ok"`
}

// Envelope is the signed, transportable artifact. PayloadB64 is the
// base64 of the canonical JSON payload; SignatureHex is the Ed25519
// signature over those raw JSON bytes; PublicKeyHex is the verifying key.
type Envelope struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureHex string `json:"signature_hex"`
	PublicKeyHex string `json:"public_key_hex"`
}

// EnsureKey loads the per-install Ed25519 private key from
// dir/attestation.key, generating and persisting a fresh one (0600) on
// first use. Mirrors the allowlist-salt storage pattern.
func EnsureKey(dir string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	path := filepath.Join(dir, KeyFileName)
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("attestation key %s: wrong size %d", path, len(data))
		}
		priv := ed25519.PrivateKey(data)
		return priv, priv.Public().(ed25519.PublicKey), nil
	} else if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read attestation key: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate attestation key: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, nil, fmt.Errorf("write attestation key: %w", err)
	}
	return priv, pub, nil
}

// Sign marshals the payload to canonical JSON and returns a signed
// Envelope.
func Sign(priv ed25519.PrivateKey, p Payload) (Envelope, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal payload: %w", err)
	}
	sig := ed25519.Sign(priv, raw)
	return Envelope{
		PayloadB64:   base64.StdEncoding.EncodeToString(raw),
		SignatureHex: hex.EncodeToString(sig),
		PublicKeyHex: hex.EncodeToString(priv.Public().(ed25519.PublicKey)),
	}, nil
}

// Verify checks an Envelope's signature against its embedded public key
// and returns the decoded payload when valid. This is what an offline
// auditor runs.
func Verify(env Envelope) (Payload, bool, error) {
	raw, err := base64.StdEncoding.DecodeString(env.PayloadB64)
	if err != nil {
		return Payload{}, false, fmt.Errorf("decode payload: %w", err)
	}
	pub, err := hex.DecodeString(env.PublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return Payload{}, false, fmt.Errorf("decode public key")
	}
	sig, err := hex.DecodeString(env.SignatureHex)
	if err != nil {
		return Payload{}, false, fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		return Payload{}, false, nil
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Payload{}, false, fmt.Errorf("unmarshal payload: %w", err)
	}
	return p, true, nil
}

// Fingerprint returns a short, human-displayable identifier for a public
// key (first 16 hex chars) — shown in the desktop Status page.
func Fingerprint(pub ed25519.PublicKey) string {
	h := hex.EncodeToString(pub)
	if len(h) > 16 {
		return h[:16]
	}
	return h
}
