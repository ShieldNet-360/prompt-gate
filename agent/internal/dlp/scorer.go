// Multi-signal scoring aggregator (pipeline step 4d).
//
// Implements the scoring formula from ARCHITECTURE.md lines 148–176:
//
//	score = score_weight
//	      + (hotword ? hotword_boost : 0)
//	      + (entropy >= entropy_min ? entropy_boost : entropy_penalty)
//	      + multi_match_boost * min(num_matches - 1, multi_match_cap)
//	      + (exclusion_hit ? exclusion_penalty : 0)
//
// Per-pattern overrides win over global weights when present.

package dlp

// multiMatchCap is the maximum number of "extra" matches that
// contribute multi_match_boost to the score. Without a cap a single
// blob full of emails would drown out higher-severity hits.
const multiMatchCap = 5

// ScoreInput is everything the scorer needs to score a single match.
type ScoreInput struct {
	Pattern        Pattern
	Match          Match
	HotwordPresent bool
	Entropy        float64
	NumMatches     int // total number of matches for this Pattern
	ExclusionHit   bool
	Weights        ScoreWeights
}

// ScoreMatch returns the aggregate score for one match.
func ScoreMatch(in ScoreInput) int {
	score := in.Pattern.ScoreWeight
	if score <= 0 {
		score = 1
	}

	if in.HotwordPresent {
		boost := in.Pattern.HotwordBoost
		if boost == 0 {
			boost = in.Weights.HotwordBoost
		}
		score += boost
	}

	if in.Pattern.EntropyMin > 0 {
		if in.Entropy >= in.Pattern.EntropyMin {
			score += in.Weights.EntropyBoost
		} else {
			score += in.Weights.EntropyPenalty
		}
	}

	if in.NumMatches > 1 {
		extra := in.NumMatches - 1
		if extra > multiMatchCap {
			extra = multiMatchCap
		}
		score += in.Weights.MultiMatchBoost * extra
	}

	if in.ExclusionHit {
		score += in.Weights.ExclusionPenalty
	}

	return score
}
