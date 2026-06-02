package dlp

import (
	"math"
	"testing"
)

func TestShannonEntropy_Empty(t *testing.T) {
	if got := ShannonEntropy(""); got != 0 {
		t.Fatalf("entropy(\"\") = %v, want 0", got)
	}
}

func TestShannonEntropy_AllSameByte(t *testing.T) {
	// A string of a single repeating byte has zero entropy.
	if got := ShannonEntropy("aaaaaaaaaaaaaa"); math.Abs(got) > 1e-9 {
		t.Fatalf("entropy(all same) = %v, want ~0", got)
	}
}

func TestShannonEntropy_Binary(t *testing.T) {
	// 50/50 mix → 1 bit per byte.
	got := ShannonEntropy("abababababab")
	if math.Abs(got-1.0) > 0.05 {
		t.Fatalf("entropy(50/50 ab) = %v, want ~1.0", got)
	}
}

func TestShannonEntropy_RandomKey(t *testing.T) {
	// A typical AWS-shaped string mixes upper-case letters and
	// digits; we expect entropy roughly 4 bits/byte. Be generous.
	got := ShannonEntropy("AKIA9F2D1JK4X8P0QRTM")
	if got < 3.0 {
		t.Fatalf("entropy(random key) = %v, want >= 3.0", got)
	}
}

func TestShannonEntropy_NeverExceedsLog2Of256(t *testing.T) {
	// A byte string can carry at most 8 bits/byte.
	s := make([]byte, 256)
	for i := range s {
		s[i] = byte(i)
	}
	if got := ShannonEntropy(string(s)); got > 8.0+1e-6 || got < 7.9 {
		t.Fatalf("entropy(0..255) = %v, want ~8.0", got)
	}
}
