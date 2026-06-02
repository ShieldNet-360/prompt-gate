// Shannon entropy calculator (pipeline step 4b).
//
// High entropy is a strong signal for "real" cryptographic material vs
// placeholder text. The DLP scorer compares ShannonEntropy(match.Value)
// against the pattern's entropy_min to add or subtract from the score.

package dlp

import "math"

// ShannonEntropy returns the per-byte Shannon entropy of s. Empty
// strings have zero entropy. Result is in bits-per-byte, so a uniform
// 256-byte random sequence approaches 8.0. Typical thresholds are
// 3.0–4.0 bits/byte for "looks random enough to be a secret".
func ShannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	total := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		h -= p * math.Log2(p)
	}
	return h
}
