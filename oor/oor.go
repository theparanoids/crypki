// Copyright 2022 Yahoo.
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

// Handler represents OOR handler.
type Handler struct {
	inRotation   bool
	inRotationMu sync.Mutex
}

// NewHandler returns an OOR Handler.
// Initial state is defined by caller, and subsequent states are handled via SIGUSR1 and SIGUSR2
func NewHandler(inRotation bool) *Handler {
	oh := &Handler{inRotation: inRotation}
	go oh.takeOutOfRotation()
	go oh.takeInRotation()
	return oh

}

// InRotation returns true if the server instance is ready to serve traffic.
func (h *Handler) InRotation() bool {
	h.inRotationMu.Lock()
	defer h.inRotationMu.Unlock()
	return h.inRotation
}

func (h *Handler) takeOutOfRotation() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	for range ch {
		h.inRotationMu.Lock()
		h.inRotation = false
		h.inRotationMu.Unlock()
	}
}

func (h *Handler) takeInRotation() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR2)
	for range ch {
		h.inRotationMu.Lock()
		h.inRotation = true
		h.inRotationMu.Unlock()
	}
}
