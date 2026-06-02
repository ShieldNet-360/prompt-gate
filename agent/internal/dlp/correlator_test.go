package dlp

import (
	"sync"
	"testing"
	"time"
)

func TestCorrelator_EmptySession(t *testing.T) {
	c := NewCorrelator(0, 0, 0)
	got, assembled := c.Combine("", "anything")
	if assembled {
		t.Errorf("empty session must not assemble; got assembled=true")
	}
	if got != "anything" {
		t.Errorf("empty session must return content as-is; got %q", got)
	}
	if c.ActiveSessions() != 0 {
		t.Errorf("empty session must not create state; got %d sessions", c.ActiveSessions())
	}
}

func TestCorrelator_NilCorrelator(t *testing.T) {
	var c *Correlator
	got, assembled := c.Combine("abc", "anything")
	if assembled || got != "anything" {
		t.Errorf("nil correlator must passthrough; got (%q, %v)", got, assembled)
	}
}

func TestCorrelator_FirstPaste_NoAssembly(t *testing.T) {
	c := NewCorrelator(0, 0, 0)
	got, assembled := c.Combine("s1", "first content")
	if assembled {
		t.Errorf("first paste in session must not assemble")
	}
	if got != "first content" {
		t.Errorf("first paste must return content as-is; got %q", got)
	}
}

func TestCorrelator_SecondPaste_Assembles(t *testing.T) {
	c := NewCorrelator(0, 0, 0)
	_, _ = c.Combine("s1", "AKIA1234")
	got, assembled := c.Combine("s1", "5678ABCDEF12345678 thanks")
	if !assembled {
		t.Errorf("second paste in same session must assemble")
	}
	want := "AKIA1234\n5678ABCDEF12345678 thanks"
	if got != want {
		t.Errorf("assembled = %q, want %q", got, want)
	}
}

func TestCorrelator_DifferentSessions_NoCrossTalk(t *testing.T) {
	c := NewCorrelator(0, 0, 0)
	_, _ = c.Combine("alice", "AKIA1234")
	got, assembled := c.Combine("bob", "5678 thanks")
	if assembled {
		t.Errorf("different session must not assemble across sessions")
	}
	if got != "5678 thanks" {
		t.Errorf("different session got = %q", got)
	}
}

func TestCorrelator_TTL_Expiry(t *testing.T) {
	c := NewCorrelator(10*time.Millisecond, 0, 0)
	_, _ = c.Combine("s1", "AKIA1234")
	time.Sleep(20 * time.Millisecond)
	got, assembled := c.Combine("s1", "5678 thanks")
	if assembled {
		t.Errorf("after TTL expiry, second paste must NOT assemble")
	}
	if got != "5678 thanks" {
		t.Errorf("post-expiry got = %q", got)
	}
}

func TestCorrelator_TailTruncation(t *testing.T) {
	c := NewCorrelator(0, 8, 0)
	first := "this is a long first paste over 8 chars"
	_, _ = c.Combine("s1", first)
	got, assembled := c.Combine("s1", "second")
	if !assembled {
		t.Fatal("expected assembly")
	}
	// Only last 8 bytes of first paste should be in the assembled view.
	want := first[len(first)-8:] + "\nsecond"
	if got != want {
		t.Errorf("assembled = %q, want %q", got, want)
	}
}

func TestCorrelator_MaxSessions_EvictsOldest(t *testing.T) {
	c := NewCorrelator(time.Hour, 0, 2)
	_, _ = c.Combine("a", "first")
	time.Sleep(2 * time.Millisecond)
	_, _ = c.Combine("b", "second")
	time.Sleep(2 * time.Millisecond)
	// Third session should evict oldest (a)
	_, _ = c.Combine("c", "third")
	if c.ActiveSessions() != 2 {
		t.Errorf("expected 2 sessions after eviction, got %d", c.ActiveSessions())
	}
	// 'a' should be gone — next paste with 'a' starts fresh
	_, assembled := c.Combine("a", "follow-up")
	if assembled {
		t.Errorf("after eviction, 'a' should be a fresh session")
	}
}

func TestCorrelator_Forget(t *testing.T) {
	c := NewCorrelator(0, 0, 0)
	_, _ = c.Combine("s1", "first")
	c.Forget("s1")
	if c.ActiveSessions() != 0 {
		t.Errorf("Forget should remove session; got %d remaining", c.ActiveSessions())
	}
	_, assembled := c.Combine("s1", "second")
	if assembled {
		t.Errorf("after Forget, next paste must be a new session")
	}
}

func TestCorrelator_ConcurrentSafe(t *testing.T) {
	c := NewCorrelator(time.Minute, 0, 1024)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_, _ = c.Combine("session"+string(rune('a'+id%26)), "paste")
			}
		}(i)
	}
	wg.Wait()
	// No assertion on exact count — eviction may have happened. Just
	// ensure no panic / race.
}

func TestTailN(t *testing.T) {
	cases := []struct {
		s    string
		n    int
		want string
	}{
		{"hello", 3, "llo"},
		{"hello", 10, "hello"},
		{"hello", 0, ""},
		{"hello", -1, ""},
		{"", 5, ""},
	}
	for _, c := range cases {
		if got := tailN(c.s, c.n); got != c.want {
			t.Errorf("tailN(%q, %d) = %q, want %q", c.s, c.n, got, c.want)
		}
	}
}

func BenchmarkCorrelator_Combine(b *testing.B) {
	c := NewCorrelator(0, 0, 0)
	for i := 0; i < b.N; i++ {
		_, _ = c.Combine("session", "hello content")
	}
}
