package rules

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Override category names. The policy engine maps "allow_admin" to
// ActionAllow and "block_admin" to ActionDeny via the standard
// category_policies table seeded at first run.
const (
	OverrideAllowCategory = "allow_admin"
	OverrideBlockCategory = "block_admin"

	overrideAllowFile = "allow-overrides.txt"
	overrideBlockFile = "block-overrides.txt"

	// SE-11: Cap the number of override entries to prevent resource exhaustion.
	maxOverrideEntries = 10000
)

// OverrideStore manages the rules/local/ directory: a pair of one-
// domain-per-line files that an admin can populate via the agent's
// API without touching the bundled rule files. The two files are
// merged on top of the bundled lookup on every Reload.
//
// All operations serialise on a single mutex — the on-disk write
// throughput is far below the loaded mutation rate, so we trade a
// little parallelism for atomic file writes.
type OverrideStore struct {
	dir string

	mu    sync.Mutex
	allow map[string]struct{}
	block map[string]struct{}
}

// NewOverrideStore loads the existing override files from dir,
// creating the directory and empty placeholder files if missing.
// An empty dir disables overrides (Add/Remove return an error,
// List returns nil, Sources returns nil).
//
// The placeholder files are created up front so the policy engine's
// source list always references them, even before the admin has
// added anything via the API. Otherwise Reload would silently keep
// using the pre-startup snapshot whenever a fresh install ran the
// first POST /api/rules/override and there was no file on disk to
// merge.
func NewOverrideStore(dir string) (*OverrideStore, error) {
	s := &OverrideStore{
		dir:   dir,
		allow: map[string]struct{}{},
		block: map[string]struct{}{},
	}
	if dir == "" {
		return s, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("override: mkdir %q: %w", dir, err)
	}
	for _, kind := range []struct {
		file string
		dest map[string]struct{}
	}{
		{overrideAllowFile, s.allow},
		{overrideBlockFile, s.block},
	} {
		path := filepath.Join(dir, kind.file)
		entries, err := readOverrideFile(path)
		switch {
		case err == nil:
			for _, d := range entries {
				kind.dest[d] = struct{}{}
			}
		case errors.Is(err, os.ErrNotExist):
			if werr := writeOverrideFile(path, nil); werr != nil {
				return nil, werr
			}
		default:
			return nil, err
		}
	}
	return s, nil
}

// Dir returns the directory the store reads / writes. May be empty.
func (s *OverrideStore) Dir() string { return s.dir }

// Add appends a domain to the allow or block list (idempotent) and
// persists the change to disk before returning.
func (s *OverrideStore) Add(domain, list string) error {
	if s.dir == "" {
		return errors.New("override: store disabled (no directory configured)")
	}
	d, err := normaliseDomain(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	target, file := s.targetForList(list)
	if target == nil {
		return fmt.Errorf("override: unknown list %q", list)
	}
	if len(target) >= maxOverrideEntries {
		return fmt.Errorf("override: maximum of %d entries reached", maxOverrideEntries)
	}
	target[d] = struct{}{}
	// When a domain is added to one list, mirror-remove it from
	// the other so the two lists stay mutually exclusive.
	if list == "allow" {
		delete(s.block, d)
		if err := writeOverrideFile(filepath.Join(s.dir, overrideBlockFile), s.sortedLocked(s.block)); err != nil {
			return err
		}
	} else {
		delete(s.allow, d)
		if err := writeOverrideFile(filepath.Join(s.dir, overrideAllowFile), s.sortedLocked(s.allow)); err != nil {
			return err
		}
	}
	return writeOverrideFile(filepath.Join(s.dir, file), s.sortedLocked(target))
}

// Remove deletes a domain from both lists (idempotent) and persists
// the change to disk.
func (s *OverrideStore) Remove(domain string) error {
	if s.dir == "" {
		return errors.New("override: store disabled (no directory configured)")
	}
	d, err := normaliseDomain(domain)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.allow, d)
	delete(s.block, d)
	if err := writeOverrideFile(filepath.Join(s.dir, overrideAllowFile), s.sortedLocked(s.allow)); err != nil {
		return err
	}
	return writeOverrideFile(filepath.Join(s.dir, overrideBlockFile), s.sortedLocked(s.block))
}

// List returns the current allow / block sets as sorted slices.
func (s *OverrideStore) List() ([]string, []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sortedLocked(s.allow), s.sortedLocked(s.block)
}

// Sources returns RuleSource entries that the lookup builder can
// merge with the bundled rules. When dir is configured both files
// are always returned (NewOverrideStore creates empty placeholders
// if needed) so the engine's source list is stable across reloads,
// even when the admin has not yet added an override.
func (s *OverrideStore) Sources() []RuleSource {
	if s.dir == "" {
		return nil
	}
	return []RuleSource{
		{Category: OverrideAllowCategory, Path: filepath.Join(s.dir, overrideAllowFile)},
		{Category: OverrideBlockCategory, Path: filepath.Join(s.dir, overrideBlockFile)},
	}
}

func (s *OverrideStore) targetForList(list string) (map[string]struct{}, string) {
	switch list {
	case "allow":
		return s.allow, overrideAllowFile
	case "block":
		return s.block, overrideBlockFile
	default:
		return nil, ""
	}
}

func (s *OverrideStore) sortedLocked(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func normaliseDomain(in string) (string, error) {
	d := strings.TrimSpace(strings.ToLower(in))
	if d == "" {
		return "", errors.New("domain is required")
	}
	// Allow a leading "." to match subdomains. Strip protocol /
	// path noise the caller might have pasted in.
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "https://")
	if idx := strings.IndexAny(d, "/?#"); idx >= 0 {
		d = d[:idx]
	}
	if d == "" || strings.ContainsAny(d, " \t") {
		return "", errors.New("invalid domain")
	}
	return d, nil
}

func readOverrideFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

func writeOverrideFile(path string, entries []string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("override: open %q: %w", tmp, err)
	}
	w := bufio.NewWriter(f)
	fmt.Fprintln(w, "# Managed by Prompt Gate admin override. Do not edit by hand.")
	for _, e := range entries {
		fmt.Fprintln(w, e)
	}
	if err := w.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
