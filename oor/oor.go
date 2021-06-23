// Package oor implements an opinionated standalone listener which can be used by load balancer
// to take the server instance out of rotation or bring it back in rotation.
// The instance will go out of rotation on receiving SIGUSR1 and can be brought back
// in rotation by sending SIGUSR1.
package oor

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

type OORHandler struct {
	inRotation   bool
	inRotationMu sync.Mutex
}

// NewHandler returns an OORHandler.
// Initial state is defined by caller, and subsequent states are handled via SIGUSR1 and SIGUSR2
func NewHandler(inRotation bool) *OORHandler {
	oh := &OORHandler{inRotation: inRotation}
	go oh.takeOutOfRotation()
	go oh.takeInRotation()
	return oh

}

// InRotation returns true if the server instance is ready to serve traffic.
func (o *OORHandler) InRotation() bool {
	o.inRotationMu.Lock()
	defer o.inRotationMu.Unlock()
	return o.inRotation
}

func (o *OORHandler) takeOutOfRotation() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for _ = range ch {
		o.inRotationMu.Lock()
		o.inRotation = false
		o.inRotationMu.Unlock()
	}
}

func (o *OORHandler) takeInRotation() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	for _ = range ch {
		o.inRotationMu.Lock()
		o.inRotation = true
		o.inRotationMu.Unlock()
	}
}
