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

	"github.com/theparanoids/crypki/server/scheduler"
)

type Work struct {
	scheduler.DoWorker

	work *Request // workChan is a channel which has a request enqueue for the worker to work on.
}

//DoWork performs the work of fetching the signer from the pool and sending it back on the response channel
func (w *Work) DoWork(workerCtx context.Context, worker *scheduler.Worker) {
	select {
	case <-workerCtx.Done():
		log.Printf("%s: worker stopped", worker.String())
		return
	default:
		reqCtx, cancel := context.WithTimeout(context.Background(), w.work.remainingTime)
		defer cancel()
		signer, err := w.work.pool.get(reqCtx)
		if err != nil {
			worker.TotalTimeout.Inc()
			log.Printf("%s: error fetching signer %v", worker.String(), err)
			w.work.respChan <- nil
			return
		}
		select {
		case <-reqCtx.Done():
			// request timed out, increment timeout context & return nil.
			worker.TotalTimeout.Inc()
			w.work.respChan <- nil
		default:
			worker.TotalProcessed.Inc()
			w.work.respChan <- signer
		}
	}
}
