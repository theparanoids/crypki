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
	"log"
	"sync"
	"testing"
	"time"

	"github.com/theparanoids/crypki/proto"
)

const jitter = 10 * time.Millisecond

type TestWork struct {
	insertTime time.Time
	name       string
	DoWorker
}

func (w *TestWork) DoWork(ctx context.Context, worker *Worker) {
	worker.TotalProcessed.Inc()
	log.Printf("overriding the work for worker %d(priority: %s), endpoint: %s insertTime %v",
		worker.Id, proto.Priority_name[int32(worker.Priority)], w.name, w.insertTime)
	// add a fixed sleep for simulating real work
	time.Sleep(jitter)
}

func TestCollectRequest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	originalStatsTimer := statsTimer
	statsTimer = 100 * time.Millisecond
	defer func() {
		statsTimer = originalStatsTimer
	}()
	tests := map[string]struct {
		ctx             context.Context
		poolSize        int
		priSchedFeature bool
		endpoint        string
		totalRequests   []int32
		enqRequest      func(wg *sync.WaitGroup, reqChan chan<- Request, endpoint string)
	}{
		"feature enabled poolsize 2": {
			ctx:             ctx,
			poolSize:        2,
			priSchedFeature: true,
			endpoint:        "/v1/FeatureEnabled",
			totalRequests:   []int32{10, 7, 3},
			enqRequest: func(wg *sync.WaitGroup, reqChan chan<- Request, endpoint string) {
				for i := 1; i <= 20; i++ {
					var priority proto.Priority
					if i%6 == 0 {
						priority = proto.Priority_Low
					} else if i%3 == 0 || i%4 == 0 {
						priority = proto.Priority_Medium
					} else {
						priority = proto.Priority_High
					}

					reqChan <- Request{
						Priority: priority,
						DoWorker: &TestWork{
							insertTime: time.Now(),
							name:       endpoint,
						},
					}
				}
				wg.Done()
			},
		},
		"feature disabled": {
			ctx:             ctx,
			poolSize:        2,
			priSchedFeature: false,
			endpoint:        "/v2/featureDisabled",
			totalRequests:   []int32{10, 0, 0},
			enqRequest: func(wg *sync.WaitGroup, reqChan chan<- Request, endpoint string) {
				for i := 1; i <= 10; i++ {
					var priority proto.Priority
					if i%4 == 0 {
						priority = proto.Priority_Low
					} else if i%3 == 0 {
						priority = proto.Priority_Medium
					} else {
						priority = proto.Priority_High
					}

					reqChan <- Request{
						Priority: priority,
						DoWorker: &TestWork{
							insertTime: time.Now(),
							name:       endpoint,
						},
					}
				}
				wg.Done()
			},
		},
		"context cancelled after enqueuing request": {
			ctx:             cancelCtx,
			poolSize:        2,
			priSchedFeature: true,
			endpoint:        "/v3/ctxCancel",
			totalRequests:   []int32{0, 0, 1},
			enqRequest: func(wg *sync.WaitGroup, reqChan chan<- Request, endpoint string) {
				for i := 1; i <= 10; {
					reqChan <- Request{
						Priority: proto.Priority_Low,
						DoWorker: &TestWork{
							insertTime: time.Now(),
							name:       endpoint,
						},
					}
					cancel()
					i++
					break
				}
				wg.Done()
			},
		},
		"feature enabled all low pri request": {
			ctx:             ctx,
			poolSize:        2,
			priSchedFeature: true,
			endpoint:        "/v4/lowPriReq",
			totalRequests:   []int32{0, 0, 10},
			enqRequest: func(wg *sync.WaitGroup, reqChan chan<- Request, endpoint string) {
				for i := 1; i <= 10; i++ {
					reqChan <- Request{
						Priority: proto.Priority_Low,
						DoWorker: &TestWork{
							insertTime: time.Now(),
							name:       endpoint,
						},
					}
				}
				wg.Done()
			},
		},
		"empty request": {
			ctx:             ctx,
			poolSize:        2,
			priSchedFeature: true,
			endpoint:        "/v5/emptyRequest",
			totalRequests:   []int32{0, 0, 0},
			enqRequest: func(wg *sync.WaitGroup, reqChan chan<- Request, endpoint string) {
				reqChan <- Request{}
				wg.Done()
			},
		},
	}

	var wg sync.WaitGroup
	for label, tt := range tests {
		tt := tt
		t.Run(label, func(t *testing.T) {
			wg.Add(1)
			reqChan := make(chan Request)
			p := &Pool{Name: tt.endpoint, PoolSize: tt.poolSize, FeatureEnabled: tt.priSchedFeature}
			go CollectRequest(tt.ctx, reqChan, p)
			// enqueue request on this channel
			go tt.enqRequest(&wg, reqChan, tt.endpoint)
			time.Sleep(100 * time.Millisecond)
		})
	}
	wg.Wait()
}

/*
func matchReqCount(t *testing.T, p *Pool, endpoint string, expected []int32) {
	type statsCount map[proto.Priority]int32
	sc := make(statsCount)
	for _, w := range p.workers {
		if _, exist := sc[w.Priority]; !exist {
			sc[w.Priority] = 0
		}
		sc[w.Priority] += w.TotalProcessed.Get()
	}

	for pri := range sc {
		log.Printf("endpoint %s got total processed %d, expected %d", endpoint, sc[pri], expected)
	}
}
*/
