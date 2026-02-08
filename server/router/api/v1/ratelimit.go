package v1

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter manages rate limiting for authentication endpoints.
type RateLimiter struct {
	limiters map[string]*rate.Limiter
	mu       sync.RWMutex
	rate     rate.Limit
	burst    int
}

// NewRateLimiter creates a new rate limiter.
// rate: requests per second
// burst: maximum burst size
func NewRateLimiter(r rate.Limit, b int) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*rate.Limiter),
		rate:     r,
		burst:    b,
	}
}

// GetLimiter returns a rate limiter for the given identifier (e.g., IP address).
func (rl *RateLimiter) GetLimiter(identifier string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	limiter, exists := rl.limiters[identifier]
	if !exists {
		limiter = rate.NewLimiter(rl.rate, rl.burst)
		rl.limiters[identifier] = limiter

		// Clean up old limiters after 1 hour
		go func() {
			time.Sleep(1 * time.Hour)
			rl.mu.Lock()
			delete(rl.limiters, identifier)
			rl.mu.Unlock()
		}()
	}

	return limiter
}

// Allow checks if a request should be allowed for the given identifier.
func (rl *RateLimiter) Allow(identifier string) bool {
	limiter := rl.GetLimiter(identifier)
	return limiter.Allow()
}
