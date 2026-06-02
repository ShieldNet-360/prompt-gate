package dlp

import "testing"

func TestScoreMatch_BaseOnly(t *testing.T) {
	got := ScoreMatch(ScoreInput{
		Pattern: Pattern{ScoreWeight: 1, Severity: SeverityCritical},
		Weights: DefaultScoreWeights(),
	})
	if got != 1 {
		t.Fatalf("base only score = %d, want 1", got)
	}
}

func TestScoreMatch_HotwordBoostsScore(t *testing.T) {
	got := ScoreMatch(ScoreInput{
		Pattern:        Pattern{ScoreWeight: 1, HotwordBoost: 2},
		HotwordPresent: true,
		Weights:        DefaultScoreWeights(),
	})
	if got != 3 {
		t.Fatalf("hotword score = %d, want 3", got)
	}
}

func TestScoreMatch_EntropyBoostAndPenalty(t *testing.T) {
	w := DefaultScoreWeights()

	highEnt := ScoreMatch(ScoreInput{
		Pattern: Pattern{ScoreWeight: 1, EntropyMin: 3.0},
		Entropy: 4.5,
		Weights: w,
	})
	if highEnt != 1+w.EntropyBoost {
		t.Fatalf("high entropy score = %d, want %d", highEnt, 1+w.EntropyBoost)
	}

	lowEnt := ScoreMatch(ScoreInput{
		Pattern: Pattern{ScoreWeight: 1, EntropyMin: 3.0},
		Entropy: 1.0,
		Weights: w,
	})
	if lowEnt != 1+w.EntropyPenalty {
		t.Fatalf("low entropy score = %d, want %d", lowEnt, 1+w.EntropyPenalty)
	}
}

func TestScoreMatch_MultiMatchCapped(t *testing.T) {
	w := DefaultScoreWeights()
	in := ScoreInput{
		Pattern:    Pattern{ScoreWeight: 1},
		NumMatches: 100,
		Weights:    w,
	}
	got := ScoreMatch(in)
	wantExtra := w.MultiMatchBoost * multiMatchCap
	if got != 1+wantExtra {
		t.Fatalf("multi-match score = %d, want %d", got, 1+wantExtra)
	}
}

func TestScoreMatch_ExclusionPenalty(t *testing.T) {
	w := DefaultScoreWeights()
	got := ScoreMatch(ScoreInput{
		Pattern:      Pattern{ScoreWeight: 1, HotwordBoost: 2},
		ExclusionHit: true,
		Weights:      w,
	})
	want := 1 + w.ExclusionPenalty
	if got != want {
		t.Fatalf("exclusion score = %d, want %d", got, want)
	}
}

func TestScoreMatch_CombinedSignals(t *testing.T) {
	// score_weight=1, hotword=+2 (per-pattern override), entropy_boost=+1,
	// multi_match=+1 (1 extra match), exclusion_penalty=-3 → total 2.
	w := DefaultScoreWeights()
	got := ScoreMatch(ScoreInput{
		Pattern: Pattern{
			ScoreWeight:  1,
			HotwordBoost: 2,
			EntropyMin:   3.0,
		},
		HotwordPresent: true,
		Entropy:        5.0,
		NumMatches:     2,
		ExclusionHit:   true,
		Weights:        w,
	})
	want := 1 + 2 + w.EntropyBoost + w.MultiMatchBoost + w.ExclusionPenalty
	if got != want {
		t.Fatalf("combined score = %d, want %d", got, want)
	}
}
