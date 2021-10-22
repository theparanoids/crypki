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
package pkcs11

import (
	"context"
	"log"

	"github.com/theparanoids/crypki/server/priority"
)

type Work struct {
	priority.DoWorker

	work Request // workChan is a channel which has a request enqueue for the worker to work on.
}

func (w *Work) DoWork(ctx context.Context, worker *priority.Worker) {
	log.Printf("starting work for %d priority %d request prio %d", worker.Id, worker.Priority, w.work.priority)
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
		worker.TotalProcessed.Inc()
		w.work.respChan <- signer
		cancel()
	}
}
