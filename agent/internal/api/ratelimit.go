package api

import (
	"net/http"
	"sync"
	"time"
)

// rateLimiter is a single-bucket token-bucket limiter intended for
// per-process throttling of /api/dlp/scan. The agent only listens on
// loopback so "per-client" granularity is unnecessary — a misbehaving
// extension is the only meaningful source of contention.
//
// The bucket holds at most burst tokens and refills at rate tokens
// per second. Each Allow() call consumes one token; over-budget calls
// observe Allow()=false until enough time elapses to refill.
type rateLimiter struct {
	mu       sync.Mutex
	burst    float64
	rate     float64
	tokens   float64
	lastFill time.Time
}

// newRateLimiter constructs a rate limiter with the given steady-state
// rate (tokens per second) and burst size. A rate <= 0 means "no
// limiting" — Allow() returns true unconditionally and the limiter is
// effectively bypassed.
func newRateLimiter(rate float64, burst int) *rateLimiter {
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		burst:    float64(burst),
		rate:     rate,
		tokens:   float64(burst),
		lastFill: time.Now(),
	}
}

// Allow returns true when a token was available and consumed, false
// when the caller should be rejected with 429.
func (l *rateLimiter) Allow() bool {
	if l == nil || l.rate <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(l.lastFill).Seconds()
	l.lastFill = now
	l.tokens += elapsed * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	if l.tokens >= 1 {
		l.tokens -= 1
		return true
	}
	return false
}

// rateLimitMiddleware wraps an http.Handler with the limiter, replying
// with 429 Too Many Requests when the bucket is empty. The Retry-After
// header is intentionally omitted — the caller's policy is "retry on
// transient failures" and the agent does not advertise an SLA.
//
// limiterFn is evaluated per request so SetScanRateLimit can replace
// the active limiter after Handler() has wired the mux without
// requiring a server restart.
func rateLimitMiddleware(limiterFn func() *rateLimiter, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l := limiterFn()
		if l != nil && !l.Allow() {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
