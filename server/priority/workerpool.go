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
	"math"

	"github.com/theparanoids/crypki/proto"
)

// pool is a struct which holds information about the workers & queue for the job.
type pool struct {
	name      string
	size      int
	workers   []*Worker
	queueSize int
	pqueueMap map[proto.Priority]chan Request
}

// initialize initializes the worker pool which has multiple workers & request queue map for queueing extra requests based on priority.
// This method creates different workers with different priorities. We currently split the num. of workers such that there
// are 4x high priority workers, 2x medium priority workers & 1x low priority workers.
func (p *pool) initialize(workerQueue chan Worker) {
	// Since there are total 7 parts (4, 2, 1) we divide the parts in given ratio & assign to each priority.
	p.workers = []*Worker{}
	nHighPriWorkers := int(math.Ceil(float64(4*p.size) / 7))
	nMedPriWorkers := int(math.Ceil(float64(2*p.size) / 7))
	for i := 0; i < p.size; i++ {
		var worker *Worker
		if i < nHighPriWorkers {
			worker = newWorker(i, proto.Priority_High, workerQueue)
		} else if i <= (nHighPriWorkers + nMedPriWorkers) {
			worker = newWorker(i, proto.Priority_Medium, workerQueue)
		} else {
			worker = newWorker(i, proto.Priority_Low, workerQueue)
		}
		p.workers = append(p.workers, worker)
	}

	p.pqueueMap = map[proto.Priority]chan Request{}
	for pri := range proto.Priority_name {
		p.pqueueMap[proto.Priority(pri)] = make(chan Request, QueueSize)
	}
}

// start starts the workers which would make them self available.
func (p *pool) start(ctx context.Context) {
	for _, worker := range p.workers {
		worker.start(ctx)
	}
	log.Println("all workers started")
}

// stop stops all the workers from processing any new requests
func (p *pool) stop(ctx context.Context) {
	for _, worker := range p.workers {
		worker.stop()
	}
	log.Println("all workers stopped")
}
