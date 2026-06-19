// Copyright 2024 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package interceptor

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/theparanoids/crypki/proto"
)

// signingMethods is the set of gRPC methods that consume an HSM signing
// operation and therefore must be rate limited per caller to protect the
// HSM from exhaustion and to prevent bulk certificate issuance from a single
// (potentially compromised) caller.
var signingMethods = map[string]bool{
	proto.Signing_PostUserSSHCertificate_FullMethodName: true,
	proto.Signing_PostHostSSHCertificate_FullMethodName: true,
	proto.Signing_PostX509Certificate_FullMethodName:    true,
	proto.Signing_PostSignBlob_FullMethodName:           true,
}

// callerLimiter tracks the token bucket and last activity for a single caller.
type callerLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter enforces a per-caller token-bucket rate limit on the signing
// endpoints. Each caller (identified by the common name of its mTLS client
// certificate) gets its own independent bucket so that one noisy or
// compromised caller cannot starve the others or saturate the HSM.
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*callerLimiter

	limit   rate.Limit
	burst   int
	ttl     time.Duration
	methods map[string]bool

	// timeNow is overridable in tests.
	timeNow func() time.Time
}

// NewRateLimiter returns a RateLimiter that allows reqsPerSec sustained signing
// requests per caller with the given burst. cleanupInterval controls how often
// idle per-caller buckets are garbage collected; a caller bucket is dropped
// once it has been idle for at least cleanupInterval. A non-positive
// cleanupInterval disables garbage collection.
func NewRateLimiter(reqsPerSec float64, burst int, cleanupInterval time.Duration) *RateLimiter {
	return &RateLimiter{
		limiters: make(map[string]*callerLimiter),
		limit:    rate.Limit(reqsPerSec),
		burst:    burst,
		ttl:      cleanupInterval,
		methods:  signingMethods,
		timeNow:  time.Now,
	}
}

// Start launches the background goroutine that garbage collects idle per-caller
// buckets. It returns immediately and stops when ctx is cancelled.
func (rl *RateLimiter) Start(ctx context.Context) {
	if rl.ttl <= 0 {
		return
	}
	go rl.cleanupLoop(ctx)
}

func (rl *RateLimiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(rl.ttl)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.cleanupOnce()
		}
	}
}

// cleanupOnce removes every per-caller bucket that has been idle for at least
// the configured TTL.
func (rl *RateLimiter) cleanupOnce() {
	cutoff := rl.timeNow().Add(-rl.ttl)
	rl.mu.Lock()
	for caller, cl := range rl.limiters {
		if cl.lastSeen.Before(cutoff) {
			delete(rl.limiters, caller)
		}
	}
	rl.mu.Unlock()
}

// numLimiters returns the current number of tracked per-caller buckets.
func (rl *RateLimiter) numLimiters() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.limiters)
}

// allow reports whether the given caller is allowed to perform one signing
// operation right now, consuming a token from the caller's bucket if so.
func (rl *RateLimiter) allow(caller string) bool {
	rl.mu.Lock()
	cl, ok := rl.limiters[caller]
	if !ok {
		cl = &callerLimiter{limiter: rate.NewLimiter(rl.limit, rl.burst)}
		rl.limiters[caller] = cl
	}
	cl.lastSeen = rl.timeNow()
	limiter := cl.limiter
	rl.mu.Unlock()
	return limiter.Allow()
}

// UnaryInterceptor returns a grpc.UnaryServerInterceptor that rate limits the
// signing endpoints on a per-caller basis. Non-signing methods (e.g. key
// lookups, health checks) are passed through untouched.
func (rl *RateLimiter) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if rl.methods[info.FullMethod] {
			caller := getPrincipalFromContext(ctx)
			if !rl.allow(caller) {
				return nil, status.Errorf(codes.ResourceExhausted, "signing rate limit exceeded for caller %q", caller)
			}
		}
		return handler(ctx, req)
	}
}
