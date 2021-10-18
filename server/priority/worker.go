package priority

import (
	"context"
	"log"

	"github.com/theparanoids/crypki/proto"
)

var PriToValMap = map[proto.Priority]int32{
	proto.Priority_Unspecified_priority: 0,
	proto.Priority_High:                 1,
	proto.Priority_Medium:               2,
	proto.Priority_Low:                  3,
}

// DoWorker ...
type DoWorker interface {
	DoWork(ctx context.Context, worker *Worker)
}

// Request ...
type Request struct {
	Priority proto.Priority
	DoWorker
}

// Worker ...
type Worker struct {
	Id             int            // Id is a unique id for the worker
	TotalProcessed []Counter      // TotalProcessed indicates the total request processed per priority by this worker.
	Priority       proto.Priority // Priority indicates the priority of the request the worker is handling.
	WorkerQueue    chan Worker    // WorkerQueue is a channel to notify the dispatcher worker is idle.
	QuitChan       chan bool      // QuitChan is a channel to cancel the worker
}

// Start method assigns the request to the worker to perform the job
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
