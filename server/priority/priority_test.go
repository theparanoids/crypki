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
	"testing"
	"time"

	"github.com/theparanoids/crypki/proto"
)

const timeout = 50 * time.Millisecond

func TestCollectRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := initializePool(t, ctx, "dummy", 10, 1)
	p.start(ctx)

	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	tests := map[string]struct {
		ctx        context.Context
		endpoint   string
		workerPool func(endpoint string) *pool
		priority   proto.Priority
		wantResp   bool
	}{
		"happy path": {
			ctx:      ctx,
			endpoint: "dummy",
			workerPool: func(endpoint string) *pool {
				p := initializePool(t, ctx, endpoint, 10, 10)
				p.start(ctx)
				return p
			},
			priority: proto.Priority_High,
			wantResp: true,
		},
		"client context deadline exceeded": {
			ctx:      timeoutCtx,
			endpoint: "/v1/endpoint",
			workerPool: func(endpoint string) *pool {
				p := initializePool(t, ctx, endpoint, 5, 10)
				p.start(ctx)
				return p
			},
			priority: proto.Priority_Medium,
			wantResp: false,
		},
	}

	requestChan := make(chan Request)
	for name, tt := range tests {
		tt := tt
		t.Run(name, func(t *testing.T) {
			dispatcherChan := make(chan Request)
			go CollectRequest(tt.ctx, requestChan, dispatcherChan, tt.endpoint)
			p := tt.workerPool(tt.endpoint)
			if tt.ctx == timeoutCtx {
				cancel()
			} else {
				req := Request{
					Priority: tt.priority,
					DoWorker: &TestWork{},
				}
				requestChan <- req
			}
			select {
			case _, ok := <-dispatcherChan:
				if tt.wantResp && !ok || !tt.wantResp && ok {
					t.Fatalf("%s: expected resp %v got %v", name, tt.wantResp, ok)
				}
			case <-tt.ctx.Done():
			}
			p.stop(ctx)
		})
	}
	cancel()
}

/*
func TestDispatchRequest(t *testing.T) {
	t.Parallel()
	requestChan := make(chan interface{})
	dispatcherChan := make(chan interface{})
	caPriv, err := createCAKey(crypki.ECDSA)
	if err != nil {
		t.Fatalf("error getting CA Priv key: %v", err)
	}
	go CollectRequest(context.Background(), requestChan, dispatcherChan, "dummy")
	priorities := []proto.Priority{proto.Priority_Unspecified_priority, proto.Priority_High, proto.Priority_Medium, proto.Priority_Low}

	tests := map[string]struct {
		desc           string
		nworkers       int
		featureEnabled bool
		requestFn      func()
	}{
		"2 workers multiple requests feature enabled": {
			desc:           "ensure workers are not idle & they always have some work in the queue",
			nworkers:       2,
			featureEnabled: true,
			requestFn: func() {
				for i := 1; i <= 10; i++ {
					priority := priorities[mrand.Intn(len(priorities))]
					req := pkcs11.Request{
						pool:          pkcs11.NewMockSignerPool(false, crypki.ECDSA, caPriv),
						Priority:      priority,
						InsertTime:    time.Now(),
						RemainingTime: 10 * time.Second,
						RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
					}
					requestChan <- req
				}
			},
		},
		"multiple workers 5 requests feature enabled": {
			desc:           "multiple workers will be idle as very few requests",
			nworkers:       10,
			featureEnabled: true,
			requestFn: func() {
				for i := 1; i <= 5; i++ {
					priority := priorities[mrand.Intn(len(priorities))]
					req := pkcs11.Request{
						pool:          pkcs11.NewMockSignerPool(false, crypki.ECDSA, caPriv),
						Priority:      priority,
						InsertTime:    time.Now(),
						RemainingTime: 10 * time.Second,
						RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
					}
					requestChan <- req
				}
			},
		},
		"multiple workers multiple request feature disabled": {
			desc:           "feature disabled so all requests are treated as high priority",
			nworkers:       10,
			featureEnabled: false,
			requestFn: func() {
				for i := 1; i <= 30; i++ {
					priority := priorities[mrand.Intn(len(priorities))]
					req := pkcs11.Request{
						pool:          pkcs11.NewMockSignerPool(false, crypki.ECDSA, caPriv),
						Priority:      priority,
						InsertTime:    time.Now(),
						RemainingTime: 10 * time.Second,
						RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
					}
					requestChan <- req
				}
			},
		},
		"few workers with medium priority requests feature enabled": {
			desc:           "all requests are medium priority so other workers do work stealing",
			nworkers:       5,
			featureEnabled: true,
			requestFn: func() {
				for i := 1; i <= 20; i++ {
					req := pkcs11.Request{
						pool:          pkcs11.NewMockSignerPool(false, crypki.ECDSA, caPriv),
						Priority:      proto.Priority_Medium,
						InsertTime:    time.Now(),
						RemainingTime: 10 * time.Second,
						RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
					}
					requestChan <- req
				}
			},
		},
		"multiple workers with low priority requests feature enabled": {
			desc:           "all requests are low priority so other workers do work stealing",
			nworkers:       5,
			featureEnabled: true,
			requestFn: func() {
				for i := 1; i <= 20; i++ {
					req := pkcs11.Request{
						pool:          pkcs11.NewMockSignerPool(false, crypki.ECDSA, caPriv),
						Priority:      proto.Priority_Low,
						InsertTime:    time.Now(),
						RemainingTime: 10 * time.Second,
						RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
					}
					requestChan <- req
				}
			},
		},
		"multiple workers with unspecified priority requests feature disabled": {
			desc:           "all requests are unspecified priority so other workers do work stealing",
			nworkers:       5,
			featureEnabled: false,
			requestFn: func() {
				for i := 1; i <= 20; i++ {
					req := pkcs11.Request{
						pool:          pkcs11.NewMockSignerPool(false, crypki.ECDSA, caPriv),
						Priority:      proto.Priority_Unspecified_priority,
						InsertTime:    time.Now(),
						RemainingTime: 10 * time.Second,
						RespChan:      make(chan pkcs11.SignerWithSignAlgorithm),
					}
					requestChan <- req
				}
			},
		},
	}
	for name, tt := range tests {
		tt := tt
		ctx, cancel := context.WithCancel(context.Background())
		t.Run(name, func(t *testing.T) {
			go DispatchRequest(ctx, dispatcherChan, tt.nworkers, tt.featureEnabled, "dummy")
			tt.requestFn()
		})
		cancel()
	}
}

*/
