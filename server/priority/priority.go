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
	"fmt"
	"log"
	"time"

	"github.com/theparanoids/crypki/pkcs11"
	"github.com/theparanoids/crypki/proto"
)

const (
	QueueSize = 100
)

// CollectRequest is responsible for receiving work requests from the client & dispatches the request to dispatcher
// & waits for another request.
func CollectRequest(ctx context.Context, requestChan <-chan interface{}, dispatcherChan chan<- interface{}, endpoint string) {
	log.Printf("start collecting requests for endpoint %q", endpoint)
	for {
		select {
		case req := <-requestChan:
			dispatcherChan <- req
		case <-ctx.Done():
			log.Printf("server context is closed, stop collector. %v", ctx.Err())
			close(dispatcherChan)
			return
		}
	}
}

// DispatchRequest waits on any new request being enqueued by CollectRequest. It parses the incoming request and assigns it to
// correct priority queue. It also starts workers based on SessionPoolSize. Workers would notify the dispatcher if they are
// idle & dispatcher assigns work based on priority. It also does work stealing. If the feature is turned off, we treat each
// request as high priority and proceed acc.
func DispatchRequest(ctx context.Context, dispatcherChan <-chan interface{}, nworkers int, priorityBasedScheduling bool, endpoint string) {
	pmap := map[proto.Priority]chan interface{}{}
	for pri := range proto.Priority_name {
		pmap[proto.Priority(pri)] = make(chan interface{}, QueueSize)
	}

	// create new workers
	workerQueue := make(chan Worker, nworkers)
	workers := createWorkers(ctx, workerQueue, nworkers)

	// Get statistics every 5 minutes for total requests processed per priority for each endpoint.
	go dumpStats(ctx, workers, endpoint, 5*time.Minute)

	go func() {
		for {
			select {
			case evt, ok := <-dispatcherChan:
				if !ok {
					dispatcherChan = nil
					return
				}
				req, ok := evt.(pkcs11.Request)
				if !ok {
					log.Printf("invalid request type %T received, skip processing it", evt)
					return
				}
				if !priorityBasedScheduling {
					pmap[proto.Priority_High] <- req
				} else {
					pmap[req.Priority] <- req
				}
			case w := <-workerQueue:
				// worker is idle, assign some work to the worker
				go w.assignWork(ctx, pmap)
			case <-ctx.Done():
				log.Printf("server context is closed, close dispatcher. %v", ctx.Err())
				return
			}
		}
	}()
}

func dumpStats(ctx context.Context, workers []*Worker, endpoint string, tickerTime time.Duration) {
	ticker := time.NewTicker(tickerTime)
	for {
		select {
		case <-ticker.C:
			priorityCount := map[int32]int32{}
			for _, worker := range workers {
				for pri := range proto.Priority_name {
					priorityCount[pri] += worker.totalProcessed[priorityToValMap[(proto.Priority(pri))]].Get()
					worker.totalProcessed[priorityToValMap[(proto.Priority(pri))]].Reset()
				}
			}
			msg := fmt.Sprintf("total requests processed for %q: ", endpoint)
			for pri, val := range proto.Priority_name {
				msg += fmt.Sprintf("%s=%d ", val, priorityCount[pri])
			}
			log.Println(msg)
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}
