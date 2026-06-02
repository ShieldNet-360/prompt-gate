package dlp

import "testing"

func TestThresholdEngine_DefaultsBlockCorrectly(t *testing.T) {
	e := NewThresholdEngine(DefaultThresholds())

	tests := []struct {
		score    int
		severity string
		want     bool
	}{
		{0, "critical", false},
		{1, "critical", true},
		{1, "high", false},
		{2, "high", true},
		{2, "medium", false},
		{3, "medium", true},
		{3, "low", false},
		{4, "low", true},
	}
	for _, tc := range tests {
		if got := e.ShouldBlock(tc.score, tc.severity); got != tc.want {
			t.Fatalf("ShouldBlock(%d, %q) = %v, want %v",
				tc.score, tc.severity, got, tc.want)
		}
	}
}

func TestThresholdEngine_UnknownSeverityUsesLow(t *testing.T) {
	e := NewThresholdEngine(DefaultThresholds())
	if !e.ShouldBlock(4, "unknown") {
		t.Fatal("unknown severity should fall back to low threshold")
	}
	if e.ShouldBlock(2, "unknown") {
		t.Fatal("unknown severity at low-but-not-enough should NOT block")
	}
}

func TestThresholdEngine_SetReplacesAtomically(t *testing.T) {
	e := NewThresholdEngine(DefaultThresholds())
	e.Set(Thresholds{Critical: 10, High: 10, Medium: 10, Low: 10})
	if e.ShouldBlock(5, "critical") {
		t.Fatal("after Set, score 5 should not block on threshold 10")
	}
	if !e.ShouldBlock(10, "critical") {
		t.Fatal("after Set, score 10 should block on threshold 10")
	}
}

func TestThresholdEngine_GetIsCopy(t *testing.T) {
	e := NewThresholdEngine(DefaultThresholds())
	t0 := e.Get()
	t0.Critical = 999
	if e.Get().Critical == 999 {
		t.Fatal("Get returned a reference, not a copy")
	}
}
