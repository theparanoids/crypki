// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package interceptor

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// neverTicks is long enough that startTicker stays parked in its select for
// the whole test, which keeps its unsynchronized read of timeRangeCounter away
// from the atomic updates InterceptorFn makes.
const neverTicks = time.Hour

// shutdownRecorder reports whether the configured ShutdownFn ran. shutdown()
// dispatches it from a new goroutine, so the test has to wait for it rather
// than read a flag.
type shutdownRecorder struct {
	called chan struct{}
}

func newShutdownRecorder() *shutdownRecorder {
	return &shutdownRecorder{called: make(chan struct{}, 4)}
}

func (r *shutdownRecorder) fn() {
	r.called <- struct{}{}
}

func (r *shutdownRecorder) wait(t *testing.T, want bool) {
	t.Helper()
	if want {
		select {
		case <-r.called:
		case <-time.After(5 * time.Second):
			t.Fatal("ShutdownFn was not called")
		}
		return
	}
	select {
	case <-r.called:
		t.Fatal("ShutdownFn was called, want no shutdown")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestShutdownCounterInterceptorFn(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		reportOnly   bool
		codes        []codes.Code
		wantShutdown bool
	}{
		"internal failures below the limit do not shut down": {
			codes:        []codes.Code{codes.Internal, codes.Internal},
			wantShutdown: false,
		},
		"a non-internal code resets the consecutive counter": {
			// Two Internal codes would otherwise reach the limit of 3; the OK
			// in between puts the count back to zero.
			codes:        []codes.Code{codes.Internal, codes.Internal, codes.OK, codes.Internal, codes.Internal},
			wantShutdown: false,
		},
		"consecutive internal failures reaching the limit shut down": {
			codes:        []codes.Code{codes.Internal, codes.Internal, codes.Internal},
			wantShutdown: true,
		},
		"report only records the limit without shutting down": {
			reportOnly:   true,
			codes:        []codes.Code{codes.Internal, codes.Internal, codes.Internal},
			wantShutdown: false,
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			recorder := newShutdownRecorder()
			counter := &ShutdownCounter{
				config: ShutdownCounterConfig{
					ReportOnly:            tt.reportOnly,
					ConsecutiveCountLimit: 3,
					TimeRangeCountLimit:   100,
					TickerDuration:        neverTicks,
					ShutdownFn:            recorder.fn,
				},
			}

			for _, code := range tt.codes {
				counter.InterceptorFn(code)
			}
			recorder.wait(t, tt.wantShutdown)
		})
	}
}

func TestShutdownCounterShutdownRunsOnce(t *testing.T) {
	t.Parallel()

	recorder := newShutdownRecorder()
	counter := &ShutdownCounter{
		config: ShutdownCounterConfig{
			ConsecutiveCountLimit: 1,
			TimeRangeCountLimit:   100,
			TickerDuration:        neverTicks,
			ShutdownFn:            recorder.fn,
		},
	}

	// Every call past the limit re-enters shutdown(), but the sync.Once means
	// the server is only asked to stop once.
	for i := 0; i < 5; i++ {
		counter.InterceptorFn(codes.Internal)
	}
	recorder.wait(t, true)
	recorder.wait(t, false)
}

func TestShutdownCounterShutdownWithoutShutdownFn(t *testing.T) {
	t.Parallel()

	// A ShutdownCounter configured without a ShutdownFn has nothing to call,
	// which must not panic.
	counter := &ShutdownCounter{config: ShutdownCounterConfig{TickerDuration: neverTicks}}
	counter.shutdown()
}

func TestShutdownCounterStartTicker(t *testing.T) {
	t.Parallel()

	t.Run("the time range counter is reset on every tick", func(t *testing.T) {
		t.Parallel()
		recorder := newShutdownRecorder()
		counter := &ShutdownCounter{
			config: ShutdownCounterConfig{
				ConsecutiveCountLimit: 100,
				TimeRangeCountLimit:   10,
				TickerDuration:        10 * time.Millisecond,
				ShutdownFn:            recorder.fn,
			},
		}
		// Set below the limit before the ticker starts, so the goroutine is
		// the only writer once it is running.
		counter.timeRangeCounter = 5

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go counter.startTicker(ctx)

		deadline := time.Now().Add(5 * time.Second)
		for atomic.LoadInt32(&counter.timeRangeCounter) != 0 {
			if time.Now().After(deadline) {
				t.Fatal("timeRangeCounter was never reset")
			}
			time.Sleep(5 * time.Millisecond)
		}
		recorder.wait(t, false)
	})

	t.Run("reaching the time range limit shuts down", func(t *testing.T) {
		t.Parallel()
		recorder := newShutdownRecorder()
		counter := &ShutdownCounter{
			config: ShutdownCounterConfig{
				ConsecutiveCountLimit: 100,
				TimeRangeCountLimit:   3,
				TickerDuration:        10 * time.Millisecond,
				ShutdownFn:            recorder.fn,
			},
		}
		counter.timeRangeCounter = 3

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go counter.startTicker(ctx)

		recorder.wait(t, true)
	})

	t.Run("reaching the time range limit in report only mode does not shut down", func(t *testing.T) {
		t.Parallel()
		recorder := newShutdownRecorder()
		counter := &ShutdownCounter{
			config: ShutdownCounterConfig{
				ReportOnly:            true,
				ConsecutiveCountLimit: 100,
				TimeRangeCountLimit:   3,
				TickerDuration:        10 * time.Millisecond,
				ShutdownFn:            recorder.fn,
			},
		}
		counter.timeRangeCounter = 3

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go counter.startTicker(ctx)

		recorder.wait(t, false)
	})

	t.Run("a cancelled context stops the ticker", func(t *testing.T) {
		t.Parallel()
		recorder := newShutdownRecorder()
		counter := &ShutdownCounter{
			config: ShutdownCounterConfig{
				ConsecutiveCountLimit: 100,
				TimeRangeCountLimit:   1,
				TickerDuration:        50 * time.Millisecond,
				ShutdownFn:            recorder.fn,
			},
		}
		counter.timeRangeCounter = 1

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		go counter.startTicker(ctx)

		// The context is already done, so the ticker returns before it can
		// notice that the counter is at its limit.
		recorder.wait(t, false)
	})
}

func TestNewShutdownCounter(t *testing.T) {
	t.Parallel()

	recorder := newShutdownRecorder()
	config := ShutdownCounterConfig{
		ConsecutiveCountLimit: 2,
		TimeRangeCountLimit:   100,
		TickerDuration:        neverTicks,
		ShutdownFn:            recorder.fn,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	counter := NewShutdownCounter(ctx, config)
	if counter == nil {
		t.Fatal("NewShutdownCounter returned nil")
	}
	if counter.config.ConsecutiveCountLimit != config.ConsecutiveCountLimit {
		t.Errorf("ConsecutiveCountLimit = %d, want %d",
			counter.config.ConsecutiveCountLimit, config.ConsecutiveCountLimit)
	}

	// The returned counter is wired up the way StatusInterceptor expects.
	interceptor := StatusInterceptor(counter.InterceptorFn)
	handler := func(context.Context, interface{}) (interface{}, error) {
		return nil, status.Error(codes.Internal, "internal failure")
	}
	for i := 0; i < 2; i++ {
		if _, err := interceptor(ctx, nil, nil, handler); err == nil {
			t.Fatal("interceptor swallowed the handler error")
		}
	}
	recorder.wait(t, true)
}
