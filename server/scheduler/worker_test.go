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
package scheduler

import (
	"context"
	"testing"
)

func initializePool(t *testing.T, ctx context.Context, endpoint string, nworkers int) *Pool {
	p := &Pool{Name: endpoint, PoolSize: nworkers}
	p.initialize()
	return p
}

func TestWorker(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	tests := map[string]struct {
		ctx     context.Context
		workers func(ctx context.Context) []*Worker
	}{
		"multiple workers multiple priorities": {
			ctx: ctx,
			workers: func(ctx context.Context) []*Worker {
				p := initializePool(t, ctx, "dummy", 2)
				p.start(ctx)
				return p.workers
			},
		},
		"ctx cancelled": {
			ctx: cancelCtx,
			workers: func(ctx context.Context) []*Worker {
				p := initializePool(t, ctx, "dummy", 3)
				p.start(ctx)
				return p.workers
			},
		},
		"worker stopped": {
			ctx: ctx,
			workers: func(ctx context.Context) []*Worker {
				p := initializePool(t, ctx, "dummy", 3)
				p.start(ctx)
				p.stop(ctx)
				return p.workers
			},
		},
	}
	for label, tt := range tests {
		tt := tt
		t.Run(label, func(t *testing.T) {
			_ = tt.workers(tt.ctx)
		})
	}
}
