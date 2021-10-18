package priority

import (
	"context"
	"log"

	"github.com/theparanoids/crypki/proto"
)

// Pool is a struct which holds information about the workers & queue for the job.
type Pool struct {
	Name      string
	Size      int
	Workers   []*Worker
	QueueSize int
	PQueueMap map[proto.Priority]chan Request
}

// Initialize initializes the workers & job queue.
func (p *Pool) Initialize(workerQueue chan Worker) {
	if p.Size < 1 {
		p.Size = 1
	}
	// Since there are total 7 parts (4, 2, 1) we divide the parts in given ratio & assign to each priority.
	p.Workers = []*Worker{}
	nHighPriWorkers := (4 * p.Size) / 7
	nMedPriWorkers := (2 * p.Size) / 7
	for i := 0; i < p.Size; i++ {
		var worker *Worker
		if i < nHighPriWorkers {
			worker = newWorker(i, proto.Priority_High, workerQueue)
		} else if i <= (nHighPriWorkers + nMedPriWorkers) {
			worker = newWorker(i, proto.Priority_Medium, workerQueue)
		} else {
			worker = newWorker(i, proto.Priority_Low, workerQueue)
		}
		p.Workers = append(p.Workers, worker)
	}

	p.PQueueMap = map[proto.Priority]chan Request{}
	for pri := range proto.Priority_name {
		p.PQueueMap[proto.Priority(pri)] = make(chan Request, QueueSize)
	}
}

// newWorker creates & returns a new worker object. Its argument is the id, the worker type & a channel
// that the worker can add itself to when it is idle.
func newWorker(workerId int, workerPriority proto.Priority, workerQ chan Worker) *Worker {
	totalProcessed := make([]Counter, len(proto.Priority_name))
	return &Worker{
		Id:             workerId,
		Priority:       workerPriority,
		WorkerQueue:    workerQ,
		TotalProcessed: totalProcessed,
		QuitChan:       make(chan bool),
	}
}

// Start ...
func (p *Pool) Start(ctx context.Context) {
	for _, worker := range p.Workers {
		worker.Start(ctx, p.PQueueMap)
	}
	log.Println("all workers started")
}
