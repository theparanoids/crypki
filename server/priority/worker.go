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

	"github.com/theparanoids/crypki/proto"
)

// PriToValMap keeps a mapping between priority type & slice indices
var PriToValMap = map[proto.Priority]int32{
	proto.Priority_Unspecified_priority: 0,
	proto.Priority_High:                 1,
	proto.Priority_Medium:               2,
	proto.Priority_Low:                  3,
}

// DoWorker is an interface for doing actual work
type DoWorker interface {
	DoWork(ctx context.Context, worker *Worker)
}

// Request is a struct which has priority & a DoWorker interface.
type Request struct {
	Priority proto.Priority
	DoWorker
}

// Worker struct stores worker information including worker id, priority & workerQ for indicating if the worker is idle or not.
type Worker struct {
	Id             int            // Id is a unique id for the worker
	Priority       proto.Priority // Priority indicates the priority of the request the worker is handling.
	TotalProcessed []Counter      // TotalProcessed indicates the total request processed per priority by this worker.
	WorkerQueue    chan Worker    // WorkerQueue is a channel to notify the dispatcher worker is idle.
	QuitChan       chan bool      // QuitChan is a channel to cancel the worker
}

// Start method assigns the request to the worker to perform the job based on priority of the worker. If no request for workers'
// priority exists, it will start stealing work from other priority queues.
// If no work available it will sleep for waitTime (currently 50 milliseconds) and retry.
func (w *Worker) Start(ctx context.Context, jobQueue map[proto.Priority]chan Request) {
	w.QuitChan = make(chan bool)

	go func() {
		for {
			// Add ourself into worker queue
			w.WorkerQueue <- *w
			select {
			case job := <-jobQueue[w.Priority]:
				if job == (Request{}) {
					log.Printf("invalid work received. skip processing it")
					continue
				}
				job.DoWork(ctx, w)
			case <-ctx.Done():
				log.Printf("worker %d stopped, request cancelled", w.Id)
				return
			case <-w.QuitChan:
				// We have been asked to stop.
				log.Printf("worker %d stopping", w.Id)
				return
				/*default:
				if request, found := stealWork(jobQueue); found {
					request.DoWork(ctx, w)
				}
				*/
			}
		}
	}()
}

/*
// stealWork will check through each priority Q & return the first request it
// finds in any of the priority Q based on the priorities.
func stealWork(jobQueue map[proto.Priority]chan Request) (*Request, bool) {
	return &Request{}, false
}
*/

func (w *Worker) Stop() {
	log.Printf("stop worker %d", w.Id)
	w.QuitChan <- true
}
