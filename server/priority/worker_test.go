// Copyright 2021 Yahoo.
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
package priority

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/pkcs11"
	"github.com/theparanoids/crypki/proto"
)

const (
	timeout = 50 * time.Millisecond
)

func TestCreateWorkers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	tests := map[string]struct {
		ctx     context.Context
		nWorker int
		wQueue  func(nWorker int) chan Worker
	}{
		"10 workers": {
			nWorker: 10,
			wQueue: func(nWorker int) chan Worker {
				return make(chan Worker, nWorker)
			},
		},
		"1 worker": {
			nWorker: 1,
			wQueue: func(nWorker int) chan Worker {
				return make(chan Worker, nWorker)
			},
		},
		"context cancelled": {
			ctx:     timeoutCtx,
			nWorker: 10,
			wQueue: func(nWorker int) chan Worker {
				return make(chan Worker, nWorker)
			},
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			if tt.ctx != timeoutCtx {
				tt.ctx = ctx
			}
			workers := createWorkers(tt.ctx, tt.wQueue(tt.nWorker), tt.nWorker)
			if tt.ctx == ctx {
				for _, w := range workers {
					w.stop()
				}
			}
		})
	}
}

// createCAKeys generates key pairs for unit tests CA based on key type.
func createCAKey(keyType crypki.PublicKeyAlgorithm) (priv crypto.Signer, err error) {
	switch keyType {
	case crypki.ECDSA:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case crypki.RSA:
		fallthrough
	default:
		return rsa.GenerateKey(rand.Reader, 2048)
	}
}

func TestCreateWorkers_PerformWork(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	priorities := []proto.Priority{proto.Priority_High, proto.Priority_Medium, proto.Priority_Low}
	tests := map[string]struct {
		nWorkers    int
		wQueue      func(nWorker int) chan Worker
		request     func(priority proto.Priority) pkcs11.Request
		stopWorkers func(workers []*Worker)
		wantErr     bool
	}{
		"2 workers RSA key": {
			nWorkers: 2,
			wQueue: func(nWorker int) chan Worker {
				return make(chan Worker, nWorker)
			},
			request: func(priority proto.Priority) pkcs11.Request {
				caPriv, err := createCAKey(crypki.RSA)
				if err != nil {
					t.Fatalf("unable to create CA keys and certificate: %v", err)
				}
				req := pkcs11.Request{
					Pool:          pkcs11.NewMockSignerPool(false, crypki.RSA, caPriv),
					Priority:      priority,
					InsertTime:    time.Now(),
					RemainingTime: 10 * time.Second,
					RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
				}
				return req
			},
			stopWorkers: func(workers []*Worker) {
				for _, w := range workers {
					w.stop()
				}
			},
			wantErr: false,
		},
		"10 workers EC key": {
			nWorkers: 10,
			wQueue: func(nWorker int) chan Worker {
				return make(chan Worker, nWorker)
			},
			request: func(priority proto.Priority) pkcs11.Request {
				caPriv, err := createCAKey(crypki.ECDSA)
				if err != nil {
					t.Fatalf("unable to create CA keys and certificate: %v", err)
				}
				req := pkcs11.Request{
					Pool:          pkcs11.NewMockSignerPool(false, crypki.ECDSA, caPriv),
					Priority:      priority,
					InsertTime:    time.Now(),
					RemainingTime: 10 * time.Second,
					RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
				}
				return req
			},
			stopWorkers: func(workers []*Worker) {
				for _, w := range workers {
					w.stop()
				}
			},
			wantErr: false,
		},
		"client timed out": {
			nWorkers: 10,
			wQueue: func(nWorker int) chan Worker {
				return make(chan Worker, nWorker)
			},
			request: func(priority proto.Priority) pkcs11.Request {
				caPriv, err := createCAKey(crypki.ECDSA)
				if err != nil {
					t.Fatalf("unable to create CA keys and certificate: %v", err)
				}
				req := pkcs11.Request{
					Pool:          pkcs11.NewMockSignerPool(false, crypki.ECDSA, caPriv),
					Priority:      priority,
					InsertTime:    time.Now(),
					RemainingTime: 0,
					RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
				}
				return req
			},
			stopWorkers: func(workers []*Worker) {
				for _, w := range workers {
					w.stop()
				}
			},
			wantErr: true,
		},
	}
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			workers := createWorkers(ctx, tt.wQueue(tt.nWorkers), tt.nWorkers)
			// send work to workers
			for _, w := range workers {
				priority := priorities[mrand.Intn(len(priorities))]
				request := tt.request(priority)
				w.workChan <- request
				signer := <-request.RespChan
				if signer == nil && !tt.wantErr {
					t.Fatalf("%s: received no response from worker", name)
				} else if signer != nil && tt.wantErr {
					t.Fatalf("%s: received response from worker when error expected", name)
				}
				// worker should be idle & waiting for more work
				select {
				case <-w.workerQueue:
				case <-ctx.Done():
				}
			}
			tt.stopWorkers(workers)
		})
	}
}
