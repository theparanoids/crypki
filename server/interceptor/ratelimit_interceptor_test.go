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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	"github.com/theparanoids/crypki/proto"
)

// ctxWithCallerCN returns a context carrying a peer with an mTLS client
// certificate whose common name is cn. An empty cn produces a peer with no
// peer certificates, mimicking a non-mTLS connection.
func ctxWithCallerCN(cn string) context.Context {
	state := tls.ConnectionState{}
	if cn != "" {
		state.PeerCertificates = []*x509.Certificate{
			{Subject: pkix.Name{CommonName: cn}},
		}
	}
	p := &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: state},
	}
	return peer.NewContext(context.Background(), p)
}

// okHandler is a no-op unary handler that records how many times it ran.
func okHandler(callCount *int) grpc.UnaryHandler {
	return func(ctx context.Context, req interface{}) (interface{}, error) {
		*callCount++
		return "ok", nil
	}
}

func TestRateLimiter_PerCallerThrottling(t *testing.T) {
	t.Parallel()

	// 0 sustained req/s with burst of 3: the first 3 calls per caller pass, the
	// 4th is throttled (no token refill within the test window).
	rl := NewRateLimiter(0, 3, 0)
	info := &grpc.UnaryServerInfo{FullMethod: proto.Signing_PostUserSSHCertificate_FullMethodName}

	calls := 0
	handler := okHandler(&calls)
	fn := rl.UnaryInterceptor()
	ctx := ctxWithCallerCN("caller-a")

	for i := 0; i < 3; i++ {
		if _, err := fn(ctx, nil, info, handler); err != nil {
			t.Fatalf("call %d: unexpected error: %v", i, err)
		}
	}

	_, err := fn(ctx, nil, info, handler)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("expected ResourceExhausted after burst, got %v", err)
	}
	if calls != 3 {
		t.Fatalf("handler should have run 3 times, ran %d", calls)
	}
}

func TestRateLimiter_IndependentBucketsPerCaller(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(0, 1, 0)
	info := &grpc.UnaryServerInfo{FullMethod: proto.Signing_PostSignBlob_FullMethodName}
	calls := 0
	handler := okHandler(&calls)
	fn := rl.UnaryInterceptor()

	// caller-a exhausts its single token.
	if _, err := fn(ctxWithCallerCN("caller-a"), nil, info, handler); err != nil {
		t.Fatalf("caller-a first call: unexpected error: %v", err)
	}
	if _, err := fn(ctxWithCallerCN("caller-a"), nil, info, handler); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("caller-a should be throttled, got %v", err)
	}

	// caller-b has its own independent bucket and is unaffected.
	if _, err := fn(ctxWithCallerCN("caller-b"), nil, info, handler); err != nil {
		t.Fatalf("caller-b should not be throttled, got %v", err)
	}
}

func TestRateLimiter_NonSigningMethodsBypassed(t *testing.T) {
	t.Parallel()

	rl := NewRateLimiter(0, 0, 0) // zero burst would throttle any limited method
	info := &grpc.UnaryServerInfo{FullMethod: proto.Signing_GetUserSSHCertificateAvailableSigningKeys_FullMethodName}
	calls := 0
	handler := okHandler(&calls)
	fn := rl.UnaryInterceptor()
	ctx := ctxWithCallerCN("caller-a")

	for i := 0; i < 5; i++ {
		if _, err := fn(ctx, nil, info, handler); err != nil {
			t.Fatalf("non-signing method should never be throttled, got %v", err)
		}
	}
	if calls != 5 {
		t.Fatalf("handler should have run 5 times, ran %d", calls)
	}
}

func TestRateLimiter_AllSigningMethodsCovered(t *testing.T) {
	t.Parallel()

	want := []string{
		proto.Signing_PostUserSSHCertificate_FullMethodName,
		proto.Signing_PostHostSSHCertificate_FullMethodName,
		proto.Signing_PostX509Certificate_FullMethodName,
		proto.Signing_PostSignBlob_FullMethodName,
	}
	for _, m := range want {
		if !signingMethods[m] {
			t.Errorf("signing method %q should be rate limited", m)
		}
	}
	if len(signingMethods) != len(want) {
		t.Errorf("unexpected number of rate-limited methods: got %d, want %d", len(signingMethods), len(want))
	}
}

func TestRateLimiter_TokenRefill(t *testing.T) {
	t.Parallel()

	// 50 req/s => one token roughly every 20ms. Burst 1.
	rl := NewRateLimiter(50, 1, 0)
	info := &grpc.UnaryServerInfo{FullMethod: proto.Signing_PostX509Certificate_FullMethodName}
	calls := 0
	handler := okHandler(&calls)
	fn := rl.UnaryInterceptor()
	ctx := ctxWithCallerCN("caller-a")

	if _, err := fn(ctx, nil, info, handler); err != nil {
		t.Fatalf("first call should pass, got %v", err)
	}
	if _, err := fn(ctx, nil, info, handler); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("second immediate call should be throttled, got %v", err)
	}

	// Wait long enough for a token to refill.
	time.Sleep(40 * time.Millisecond)
	if _, err := fn(ctx, nil, info, handler); err != nil {
		t.Fatalf("call after refill should pass, got %v", err)
	}
}

func TestRateLimiter_Cleanup(t *testing.T) {
	t.Parallel()

	ft := &fakeTimer{t: time.Unix(1000, 0)}
	var mu sync.Mutex
	rl := NewRateLimiter(10, 5, time.Minute)
	rl.timeNow = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return ft.t
	}

	// Register a caller bucket.
	rl.allow("stale-caller")
	if got := rl.numLimiters(); got != 1 {
		t.Fatalf("expected 1 limiter, got %d", got)
	}

	// Advance time well beyond the TTL and run one cleanup pass.
	mu.Lock()
	ft.t = ft.t.Add(2 * time.Minute)
	mu.Unlock()
	rl.cleanupOnce()

	if got := rl.numLimiters(); got != 0 {
		t.Fatalf("expected stale limiter to be cleaned up, got %d", got)
	}
}
