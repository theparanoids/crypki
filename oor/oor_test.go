// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package oor

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"
)

// disableDefaultSignalAction keeps a subscriber registered for SIGUSR1 and
// SIGUSR2 for the whole test. Without one, a signal that arrives before the
// Handler goroutines have called signal.Notify takes the default action for
// those signals, which is to terminate the test binary.
func disableDefaultSignalAction(t *testing.T) {
	t.Helper()
	sink := make(chan os.Signal, 8)
	signal.Notify(sink, syscall.SIGUSR1, syscall.SIGUSR2)
	t.Cleanup(func() { signal.Stop(sink) })
}

// waitForRotation sends sig until the handler reports want, or fails the test.
// The signal is resent because NewHandler registers its subscribers from
// goroutines, so an early signal can be delivered before either is listening.
// Both signals are idempotent with respect to the state being waited for, so
// resending cannot overshoot.
func waitForRotation(t *testing.T, h *Handler, sig syscall.Signal, want bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(os.Getpid(), sig); err != nil {
			t.Fatalf("failed to send %v: %v", sig, err)
		}
		for i := 0; i < 20; i++ {
			if h.InRotation() == want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	t.Fatalf("InRotation() = %v after %v, want %v", h.InRotation(), sig, want)
}

func TestNewHandlerInitialState(t *testing.T) {
	disableDefaultSignalAction(t)

	for _, inRotation := range []bool{true, false} {
		if got := NewHandler(inRotation).InRotation(); got != inRotation {
			t.Errorf("NewHandler(%v).InRotation() = %v, want %v", inRotation, got, inRotation)
		}
	}
}

func TestHandlerSignals(t *testing.T) {
	disableDefaultSignalAction(t)

	h := NewHandler(true)

	// SIGUSR1 takes the instance out of rotation, SIGUSR2 brings it back, and
	// either is a no-op once the instance is already in that state.
	waitForRotation(t, h, syscall.SIGUSR1, false)
	waitForRotation(t, h, syscall.SIGUSR1, false)
	waitForRotation(t, h, syscall.SIGUSR2, true)
	waitForRotation(t, h, syscall.SIGUSR2, true)
	waitForRotation(t, h, syscall.SIGUSR1, false)
}
