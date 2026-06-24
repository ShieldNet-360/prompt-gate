package attestation

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func samplePayload() Payload {
	return Payload{
		AgentVersion:    "1.1.0",
		OSType:          "darwin",
		OSArch:          "arm64",
		ExportedAtUnix:  1_700_000_000,
		DLPPatternCount: 165,
		DLPRulesSHA256:  "abc123",
		ScansTotal:      42,
		BlocksTotal:     7,
		TamperOK:        true,
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	priv, _, err := EnsureKey(dir)
	if err != nil {
		t.Fatalf("EnsureKey: %v", err)
	}
	env, err := Sign(priv, samplePayload())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	got, ok, err := Verify(env)
	if err != nil || !ok {
		t.Fatalf("Verify ok=%v err=%v", ok, err)
	}
	if !reflect.DeepEqual(got, samplePayload()) {
		t.Errorf("round-trip payload mismatch: %+v", got)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	dir := t.TempDir()
	priv, _, _ := EnsureKey(dir)
	env, _ := Sign(priv, samplePayload())
	// flip a character in the payload — signature must no longer verify
	env.PayloadB64 = "X" + env.PayloadB64[1:]
	_, ok, _ := Verify(env)
	if ok {
		t.Error("tampered payload verified true, want false")
	}
}

func TestEnsureKeyIsStableAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	_, pub1, _ := EnsureKey(dir)
	_, pub2, err := EnsureKey(dir) // second call must load, not regenerate
	if err != nil {
		t.Fatalf("EnsureKey 2: %v", err)
	}
	if !reflect.DeepEqual(pub1, pub2) {
		t.Error("key regenerated across calls; should be stable")
	}
}

func TestSignIsDeterministicPayload(t *testing.T) {
	dir := t.TempDir()
	priv, _, _ := EnsureKey(dir)
	a, _ := Sign(priv, samplePayload())
	b, _ := Sign(priv, samplePayload())
	if a.PayloadB64 != b.PayloadB64 {
		t.Error("payload JSON is non-deterministic")
	}
}

// The attested payload must never carry sensitive fields.
func TestPayloadHasNoSensitiveFields(t *testing.T) {
	env, _ := func() (Envelope, error) {
		priv, _, _ := EnsureKey(t.TempDir())
		return Sign(priv, samplePayload())
	}()
	bad := regexp.MustCompile(`(?i)url|domain|host|ip|content|match|path|secret|token`)
	// decode and scan the JSON field names + values
	got, _, _ := Verify(env)
	blob := strings.ToLower(strings.Join([]string{
		got.AgentVersion, got.OSType, got.OSArch, got.DLPRulesSHA256,
	}, " "))
	if bad.MatchString(blob) {
		t.Errorf("attestation payload contains a sensitive-looking value: %q", blob)
	}
}

func TestKeyFileLocation(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := EnsureKey(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, KeyFileName)); err != nil {
		t.Errorf("key not written to %s: %v", KeyFileName, err)
	}
}
