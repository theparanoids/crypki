// Copyright 2021 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package scheduler

import (
	"context"
	"log"
	"time"
)

var statsTimer = 5 * time.Minute

// CollectRequest is responsible for receiving work requests from the client & enqueues the request to the requestQueue as part of a go routine
func CollectRequest(ctx context.Context, requestChan <-chan Request, p *Pool) {
	// create new worker pool for the given endpoint
	p.initialize()
	p.start(ctx)

	go p.dumpStats(ctx, statsTimer)

	for {
		select {
		case req := <-requestChan:
			go p.enqueueRequest(ctx, &req, p.FeatureEnabled)
		case <-ctx.Done():
			log.Printf("server context is closed for %s, stop collecting request. %v", p.Name, ctx.Err())
			return
		}
	}
}
