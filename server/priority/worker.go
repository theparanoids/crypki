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
	"time"

	"github.com/theparanoids/crypki/pkcs11"
	"github.com/theparanoids/crypki/proto"
)

const waitTime = 50 * time.Millisecond

// Worker holds individual worker info used to create and send work by dispatcher.
type Worker struct {
	id             int                 // id is a unique id for the worker
	totalProcessed []Counter           // totalProcessed indicates the total request processed per priority by this worker.
	priority       proto.Priority      // priority indicates the priority of the request the worker is handling.
	workChan       chan pkcs11.Request // workChan is a channel which has a request enqueue for the worker to work on.
	workerQueue    chan Worker         // workerQueue is a channel to notify the dispatcher worker is idle.
	quitChan       chan bool           // quitChan is a channel to cancel the worker
}

// newWorker creates & returns a new worker object. Its argument is the id, the worker type & a channel
// that the worker can add itself to when it is idle.
func newWorker(workerId int, workerPriority proto.Priority, workerQueue chan Worker) *Worker {
	totalProcessed := make([]Counter, len(proto.Priority_name))
	return &Worker{
		id:             workerId,
		priority:       workerPriority,
		workChan:       make(chan pkcs11.Request),
		workerQueue:    workerQueue,
		quitChan:       make(chan bool),
		totalProcessed: totalProcessed,
	}
}

func getPriorityToValMap(priority proto.Priority) int32 {
	switch priority {
	case proto.Priority_Unspecified_priority:
		return 0
	case proto.Priority_High:
		return 1
	case proto.Priority_Medium:
		return 2
	case proto.Priority_Low:
		return 3
	}
	return 0
}

// createWorkers creates different workers with different priorities. We currently split the num. of workers
// such that there are 4x high priority workers, 2x medium priority workers & 1x low priority workers. This method ensures
// we do not starve lower priority requests. As an argument it takes the total number of workers we should create.
func createWorkers(ctx context.Context, workerQueue chan Worker, nWorkers int) []*Worker {
	// Since there are total 7 parts (4, 2, 1) we divide the parts in given ratio & assign to each priority.
	var workers []*Worker
	nHighPriWorkers := (4 * nWorkers) / 7
	nMedPriWorkers := (2 * nWorkers) / 7
	for i := 0; i < nWorkers; i++ {
		var worker *Worker
		if i < nHighPriWorkers {
			worker = newWorker(i, proto.Priority_High, workerQueue)
		} else if i <= (nHighPriWorkers + nMedPriWorkers) {
			worker = newWorker(i, proto.Priority_Medium, workerQueue)
		} else {
			worker = newWorker(i, proto.Priority_Low, workerQueue)
		}
		worker.start(ctx)
		workers = append(workers, worker)
	}
	return workers
}

// assignWork assigns the request to the worker based on the priority of the worker. If no request of the worker priority
// exists, worker will start stealing work from the higher priority queue. If no work for higher priority Q exists, it will
// sleep for 50 millisecond and retry.
func (w *Worker) assignWork(ctx context.Context, pmap map[proto.Priority]chan pkcs11.Request) {
	for {
		select {
		case request := <-pmap[w.priority]:
			w.workChan <- request
			return
		case <-ctx.Done():
			log.Printf("request cancelled, stop assigning work")
			return
		default:
			if request, found := stealWork(pmap); found {
				w.workChan <- request
				return
			}
			// Did not find any work to steal, sleep for 50 milliseconds before retrying.
			time.Sleep(waitTime)
		}
	}
}

// stealWork will check through each priority Q & return the first request it finds in any of the priority Q based on the priorities.
func stealWork(pmap map[proto.Priority]chan pkcs11.Request) (pkcs11.Request, bool) {
	// In order to prioritize highPriority request we add 2 select statements.
	// First to check if any highPriority requests exists, if not we check all entries in the map to look for work to steal from.
	select {
	case work := <-pmap[proto.Priority_High]:
		return work, true
	default:
	}
	for pri := range pmap {
		select {
		case work := <-pmap[pri]:
			return work, true
		default:
		}
	}
	return pkcs11.Request{}, false
}

// start method performs the work for the worker. It will fetch the signer from the pool & assign it back to the caller
// using the respChan.
func (w *Worker) start(ctx context.Context) {
	go func() {
		for {
			// Add ourself into worker queue
			w.workerQueue <- *w
			select {
			case work := <-w.workChan:
				ctx, cancel := context.WithTimeout(context.Background(), work.RemainingTime)
				signer, err := work.Pool.Get(ctx)
				if err != nil {
					log.Printf("error fetching signer %v", err)
					work.RespChan <- nil
					cancel()
					continue
				}
				w.totalProcessed[getPriorityToValMap(work.Priority)].Inc()
				work.RespChan <- signer
				cancel()
			case <-ctx.Done():
				log.Printf("worker %d stopped, request cancelled", w.id)
				return
			case <-w.quitChan:
				// We have been asked to stop.
				log.Printf("worker %d stopping", w.id)
				return
			}
		}
	}()
}

func (w *Worker) stop() {
	log.Printf("stop worker %d", w.id)
	w.quitChan <- true
}
