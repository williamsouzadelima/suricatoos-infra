package transport

import "time"

// Backoff returns an exponential backoff with full jitter for a 0-based attempt:
// it doubles base each attempt up to max, then returns a random duration in
// [0, d). rnd must return a value in [0,1) (e.g. math/rand.Float64); injecting it
// keeps the function deterministic in tests.
func Backoff(attempt int, base, max time.Duration, rnd func() float64) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := base
	for i := 0; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max || d <= 0 {
		d = max
	}
	return time.Duration(rnd() * float64(d))
}
