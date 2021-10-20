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
	"math/rand"
	"testing"
	"time"

	"github.com/theparanoids/crypki/proto"
)

type TestWork struct {
	remTime time.Duration
	DoWorker
}

func (w *TestWork) DoWork(ctx context.Context, worker *Worker) {
	log.Printf("overriding the work for %d", worker.Id)
}

func initializePool(t *testing.T, ctx context.Context, endpoint string, nworkers int, queueSize int) *pool {
	workerQ := make(chan Worker, 10)
	p := &pool{name: endpoint, size: nworkers, queueSize: queueSize}
	p.initialize(workerQ)
	return p
}

func TestWorker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	priorities := []proto.Priority{proto.Priority_Unspecified_priority, proto.Priority_High, proto.Priority_Medium, proto.Priority_Low}
	tests := map[string]struct {
		ctx     context.Context
		workers func(ctx context.Context) []*Worker
	}{
		"multiple workers multiple priorities": {
			ctx: ctx,
			workers: func(ctx context.Context) []*Worker {
				var workers []*Worker
				for i := 0; i < 10; i++ {
					priority := priorities[rand.Intn(len(priorities))]
					w := newWorker(i, priority, make(chan Worker, 10))
					w.start(ctx)
					workers = append(workers, w)
				}
				return workers
			},
		},
		"ctx cancelled": {
			ctx: cancelCtx,
			workers: func(ctx context.Context) []*Worker {
				var workers []*Worker
				for i := 0; i < 3; i++ {
					priority := priorities[rand.Intn(len(priorities))]
					w := newWorker(i, priority, make(chan Worker, 3))
					w.start(ctx)
					workers = append(workers, w)
				}
				return workers
			},
		},
		"worker stopped": {
			ctx: ctx,
			workers: func(ctx context.Context) []*Worker {
				var workers []*Worker
				for i := 0; i < 3; i++ {
					priority := priorities[rand.Intn(len(priorities))]
					w := newWorker(i, priority, make(chan Worker, 3))
					w.start(ctx)
					workers = append(workers, w)
				}
				return workers
			},
		},
	}
	for label, tt := range tests {
		tt := tt
		t.Run(label, func(t *testing.T) {
			workers := tt.workers(tt.ctx)
			for _, w := range workers {
				work := <-w.WorkerQueue
				if tt.ctx == cancelCtx {
					cancel()
					continue
				} else if label == "worker stopped" {
					w.stop()
					continue
				}
				work.WorkChan <- Request{
					Priority: proto.Priority_High,
					DoWorker: &TestWork{remTime: 1 * time.Minute},
				}
				w.stop()
			}
		})
	}
}
