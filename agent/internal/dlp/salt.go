// Per-install salt for the Phase 8 Config H allowlist.
//
// The salt is 32 random bytes generated once on first run and
// persisted to ~/.prompt-gate/allowlist-salt with 0600 perms. Hash
// inputs to the allowlist are SHA-256(salt || normalized(value)),
// so a stolen `dlp_allowlist` table (without the salt file) cannot
// be reverse-looked up against a wordlist of common secret values.
//
// Privacy invariant: the salt file itself contains no per-event
// data — only the random salt bytes. Losing the salt does not leak
// any user-derived information; it merely invalidates every
// allowlist entry (a fresh salt produces a fresh hash space).

package dlp

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// saltSize is the byte length of a newly-generated salt. 32 bytes =
// 256 bits, comfortably more than the SHA-256 output it feeds.
const saltSize = 32

// LoadOrGenerateSalt reads the salt at path. If the file does not
// exist, a fresh 32-byte random salt is generated, persisted with
// 0600 perms, and returned. If the file exists but is empty or
// malformed, an error is returned (the caller should NOT silently
// overwrite — that would invalidate every existing allowlist entry).
func LoadOrGenerateSalt(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("allowlist salt path is empty")
	}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		s, parseErr := parseSaltHex(data)
		if parseErr != nil {
			return nil, fmt.Errorf("allowlist salt: %w", parseErr)
		}
		return s, nil
	case errors.Is(err, fs.ErrNotExist):
		return generateAndPersistSalt(path)
	default:
		return nil, fmt.Errorf("allowlist salt: read %s: %w", path, err)
	}
}

func generateAndPersistSalt(path string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("allowlist salt: mkdir: %w", err)
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("allowlist salt: random: %w", err)
	}
	encoded := []byte(hex.EncodeToString(salt))
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("allowlist salt: write %s: %w", path, err)
	}
	return salt, nil
}

func parseSaltHex(data []byte) ([]byte, error) {
	// Tolerate a trailing newline that some editors add silently.
	trimmed := data
	for len(trimmed) > 0 && (trimmed[len(trimmed)-1] == '\n' || trimmed[len(trimmed)-1] == '\r') {
		trimmed = trimmed[:len(trimmed)-1]
	}
	if len(trimmed) == 0 {
		return nil, errors.New("salt file is empty")
	}
	if len(trimmed) != saltSize*2 {
		return nil, fmt.Errorf("salt has %d hex chars, expected %d", len(trimmed), saltSize*2)
	}
	out := make([]byte, saltSize)
	if _, err := hex.Decode(out, trimmed); err != nil {
		return nil, fmt.Errorf("salt is not valid hex: %w", err)
	}
	return out, nil
}
