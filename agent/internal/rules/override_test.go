package rules

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestOverrideStoreEmptyDir(t *testing.T) {
	s, err := NewOverrideStore("")
	if err != nil {
		t.Fatalf("NewOverrideStore: %v", err)
	}
	if err := s.Add("example.com", "allow"); err == nil {
		t.Fatalf("expected Add to fail with no dir configured")
	}
	if got := s.Sources(); got != nil {
		t.Fatalf("expected nil sources, got %+v", got)
	}
}

// Regression: Sources must surface both override paths the moment
// the directory is configured, even before any Add has run. The
// agent wires these into the policy engine's source list at
// startup so a later POST /api/rules/override + Reload picks up
// the new entries — gating on "do entries exist yet?" caused the
// new domain to be silently ignored on fresh installs.
func TestOverrideStoreSourcesAvailableBeforeAdd(t *testing.T) {
	dir := t.TempDir()
	s, err := NewOverrideStore(dir)
	if err != nil {
		t.Fatalf("NewOverrideStore: %v", err)
	}
	got := s.Sources()
	if len(got) != 2 {
		t.Fatalf("expected 2 sources when dir is configured, got %d: %+v", len(got), got)
	}
	for _, src := range got {
		if _, err := os.Stat(src.Path); err != nil {
			t.Fatalf("Sources references missing file %q: %v", src.Path, err)
		}
	}
	// Sanity check: Build must succeed against the empty placeholders.
	if _, err := Build(got); err != nil {
		t.Fatalf("Build on empty overrides: %v", err)
	}
}

// Regression: when the admin adds a domain after startup, the on-
// disk file must be picked up by a subsequent Build/Reload using
// the same sources slice we registered with the engine at startup.
func TestOverrideStoreReloadSeesNewEntries(t *testing.T) {
	dir := t.TempDir()
	s, err := NewOverrideStore(dir)
	if err != nil {
		t.Fatalf("NewOverrideStore: %v", err)
	}
	srcs := s.Sources()
	if err := s.Add("late.example.com", "block"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	lookup, err := Build(srcs)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cat, ok := lookup.Lookup("late.example.com"); !ok || cat != OverrideBlockCategory {
		t.Fatalf("override not seen by Build: cat=%q ok=%v", cat, ok)
	}
}

func TestOverrideStoreAddRemoveList(t *testing.T) {
	dir := t.TempDir()
	s, err := NewOverrideStore(dir)
	if err != nil {
		t.Fatalf("NewOverrideStore: %v", err)
	}
	if err := s.Add("Example.COM", "allow"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Add("bad.example.com", "block"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Adding to allow when present in block must move it.
	if err := s.Add("bad.example.com", "allow"); err != nil {
		t.Fatalf("Add move: %v", err)
	}
	a, b := s.List()
	sort.Strings(a)
	sort.Strings(b)
	wantA := []string{"bad.example.com", "example.com"}
	if !reflect.DeepEqual(a, wantA) {
		t.Fatalf("allow list mismatch: %v != %v", a, wantA)
	}
	if len(b) != 0 {
		t.Fatalf("expected block list empty after move, got %v", b)
	}

	if err := s.Remove("example.com"); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	a, _ = s.List()
	if reflect.DeepEqual(a, []string{"bad.example.com"}) == false {
		t.Fatalf("after remove want [bad.example.com], got %v", a)
	}

	// Files must exist on disk and round-trip through a second
	// instance.
	if _, err := os.Stat(filepath.Join(dir, overrideAllowFile)); err != nil {
		t.Fatalf("allow file missing: %v", err)
	}
	s2, err := NewOverrideStore(dir)
	if err != nil {
		t.Fatalf("re-load: %v", err)
	}
	a, _ = s2.List()
	if !reflect.DeepEqual(a, []string{"bad.example.com"}) {
		t.Fatalf("reloaded allow list mismatch: %v", a)
	}
}

func TestOverrideStoreInvalidDomain(t *testing.T) {
	s, _ := NewOverrideStore(t.TempDir())
	if err := s.Add("", "allow"); err == nil {
		t.Fatalf("expected error for empty domain")
	}
	if err := s.Add("foo bar", "allow"); err == nil {
		t.Fatalf("expected error for whitespace in domain")
	}
	if err := s.Add("ok.com", "elsewhere"); err == nil {
		t.Fatalf("expected error for unknown list")
	}
}

func TestOverrideStoreNormalisesURL(t *testing.T) {
	s, _ := NewOverrideStore(t.TempDir())
	if err := s.Add("https://Foo.Example.com/bar", "block"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	_, b := s.List()
	if !reflect.DeepEqual(b, []string{"foo.example.com"}) {
		t.Fatalf("expected normalised domain, got %v", b)
	}
}

func TestOverrideStoreSourcesMergeWithLookup(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewOverrideStore(dir)
	_ = s.Add("only-local.example", "block")

	// Build a bundled lookup with a different domain so we can
	// confirm the override merges cleanly without corrupting it.
	bundled := filepath.Join(t.TempDir(), "ads.txt")
	if err := os.WriteFile(bundled, []byte("ads.example.com\n"), 0o644); err != nil {
		t.Fatalf("write bundled: %v", err)
	}
	srcs := []RuleSource{{Category: "ads", Path: bundled}}
	srcs = append(srcs, s.Sources()...)
	lookup, err := Build(srcs)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if cat, ok := lookup.Lookup("ads.example.com"); !ok || cat != "ads" {
		t.Fatalf("bundled rule lost: %s ok=%v", cat, ok)
	}
	if cat, ok := lookup.Lookup("only-local.example"); !ok || cat != OverrideBlockCategory {
		t.Fatalf("override missing: %s ok=%v", cat, ok)
	}
}
