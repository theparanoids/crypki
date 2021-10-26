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
	"fmt"
	"log"
	"time"

	"github.com/theparanoids/crypki/proto"
)

// Pool is a struct which holds information about the workers & queue for the job.
type Pool struct {
	Name           string
	PoolSize       int
	FeatureEnabled bool
	workers        []*Worker
	requestQueue   map[proto.Priority]chan *Request
}

// initialize initializes the worker Pool which has multiple workers & request queue map for queueing extra requests based on priority.
// This method creates different workers with different priorities. We currently create 4x high priority workers, 2x medium priority &
// 1x low priority workers based on the signerPoolSize.
func (p *Pool) initialize() {
	p.workers = []*Worker{}
	p.requestQueue = map[proto.Priority]chan *Request{}

	mp := map[proto.Priority]int{
		proto.Priority_High:   4 * p.PoolSize,
		proto.Priority_Medium: 2 * p.PoolSize,
		proto.Priority_Low:    p.PoolSize,
	}
	var i, j int
	for pri, size := range mp {
		for ; i < j+size; i++ {
			worker := newWorker(i, pri)
			p.workers = append(p.workers, worker)
		}
		j += size
		p.requestQueue[pri] = make(chan *Request, size)
	}
}

// start starts the workers which would make them self available.
func (p *Pool) start(ctx context.Context) {
	for _, worker := range p.workers {
		worker.start(ctx, p.requestQueue)
	}
	log.Printf("all workers started for %q", p.Name)
}

// stop stops all the workers from processing any new requests
func (p *Pool) stop(ctx context.Context) {
	for _, worker := range p.workers {
		worker.stop()
	}
	log.Printf("all workers stopped for %q", p.Name)
}

// enqueueRequest enqueues any new incoming request to appropriate request queue based on the priority.
// This may be a blocking method if all the workers are occupied & the queue is full.
func (p *Pool) enqueueRequest(ctx context.Context, req *Request, prioritySchedulingEnabled bool) {
	if !prioritySchedulingEnabled {
		p.requestQueue[proto.Priority_High] <- req
	} else {
		p.requestQueue[req.Priority] <- req
	}
}

// dumpStats runs at a regular interval & dumps info like total requests processed & total requests timed out.
func (p *Pool) dumpStats(ctx context.Context, tickerTime time.Duration) {
	ticker := time.NewTicker(tickerTime)
	type count struct {
		totalProcessed uint32
		totalTimeout   uint32
	}
	type statsCount map[proto.Priority]*count
	for {
		select {
		case <-ticker.C:
			sc := make(statsCount)
			for _, w := range p.workers {
				if _, exist := sc[w.Priority]; !exist {
					sc[w.Priority] = &count{}
				}
				sc[w.Priority].totalProcessed += w.TotalProcessed.Get()
				sc[w.Priority].totalTimeout += w.TotalTimeout.Get()
				w.TotalProcessed.Reset()
				w.TotalTimeout.Reset()
			}
			msg := fmt.Sprintf("total requests processed for %q: ", p.Name)
			for pri := range sc {
				msg += fmt.Sprintf("%s=%d ", pri, sc[pri].totalProcessed)
			}
			log.Println(msg)
			msg = fmt.Sprintf("total requests that timed out for %q: ", p.Name)
			for pri := range sc {
				msg += fmt.Sprintf("%s=%d ", pri, sc[pri].totalTimeout)
			}
			log.Println(msg)
			msg = fmt.Sprintf("requests currently enqueued for %q: ", p.Name)
			for key, val := range p.requestQueue {
				msg += fmt.Sprintf("%s=%d ", key, len(val))
			}
			log.Println(msg)
		case <-ctx.Done():
			ticker.Stop()
			return
		}
	}
}
