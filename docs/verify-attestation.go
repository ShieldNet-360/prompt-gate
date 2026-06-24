//go:build ignore

// verify-attestation is a standalone, dependency-free verifier for a
// Prompt Gate attestation envelope. It reads the envelope JSON from
// stdin, checks the Ed25519 signature against the embedded public key,
// and prints the attested payload. An auditor can run it without the
// rest of the repo.
//
//	curl -s -H "Authorization: Bearer $(cat ~/.prompt-gate/api-token)" \
//	  http://127.0.0.1:9191/api/attestation | go run docs/verify-attestation.go
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

type envelope struct {
	PayloadB64   string `json:"payload_b64"`
	SignatureHex string `json:"signature_hex"`
	PublicKeyHex string `json:"public_key_hex"`
}

func main() {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		fail(err)
	}
	var e envelope
	if err := json.Unmarshal(data, &e); err != nil {
		fail(fmt.Errorf("parse envelope: %w", err))
	}
	raw, err := base64.StdEncoding.DecodeString(e.PayloadB64)
	if err != nil {
		fail(fmt.Errorf("decode payload: %w", err))
	}
	pub, err := hex.DecodeString(e.PublicKeyHex)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		fail(fmt.Errorf("decode public key"))
	}
	sig, err := hex.DecodeString(e.SignatureHex)
	if err != nil {
		fail(fmt.Errorf("decode signature: %w", err))
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), raw, sig) {
		fmt.Println("SIGNATURE INVALID")
		os.Exit(1)
	}
	fmt.Println("SIGNATURE VALID")
	fmt.Printf("device key fingerprint: %s\n", e.PublicKeyHex[:16])
	fmt.Println(string(raw))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "verify-attestation:", err)
	os.Exit(2)
}
