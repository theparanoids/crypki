package pkcs11

import (
	"context"
	"log"

	"github.com/theparanoids/crypki/server/priority"
)

type Work struct {
	work Request // workChan is a channel which has a request enqueue for the worker to work on.
}

func (w *Work) DoWork(ctx context.Context, worker *priority.Worker) {
	log.Printf("starting work for %d priority %d", worker.Id, worker.Priority)
	select {
	case <-ctx.Done():
		log.Printf("worker %d stopped", worker.Id)
		return
	default:
		ctx, cancel := context.WithTimeout(context.Background(), w.work.remainingTime)
		signer, err := w.work.pool.get(ctx)
		if err != nil {
			log.Printf("error fetching signer %v", err)
			w.work.respChan <- nil
			cancel()
			return
		}
		worker.TotalProcessed[priority.PriToValMap[w.work.priority]].Inc()
		w.work.respChan <- signer
		cancel()
	}
}
