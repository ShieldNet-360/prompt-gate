package dlp

import "testing"

// A panic while evaluating a single pattern must not crash the agent —
// the worker goroutines run outside any net/http recover, so an unhandled
// panic there would take the whole process (and everyone's traffic) down.
// evaluatePatternSafe recovers and fails open (empty, non-blocking
// result). A nil pattern forces a nil-deref panic inside evaluatePattern.
func TestEvaluatePatternSafe_RecoversAndFailsOpen(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("evaluatePatternSafe must absorb the panic, but it propagated: %v", r)
		}
	}()

	res := evaluatePatternSafe(
		"some content with a secret",
		nil, // nil pattern → evaluatePattern panics on pat.MinMatches
		[]Match{{Value: "x"}},
		nil,
		ScoreWeights{},
		nil,
		SourceContext{},
		nil,
	)
	if res.Blocked {
		t.Error("recovered result should fail OPEN (Blocked=false)")
	}
}
