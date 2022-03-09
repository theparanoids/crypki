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

// DoWork performs the work of fetching the signer from the pool and sending it back on the response channel.
// If the client cancels the request or times out, the worker should not wait indefinitely for getting the signer from the
// pool. Also, we have a max HSM timeout which enforces the worker to wait for max duration to fetch the signer from pool
// & return if it exceeds that.
func (w *Work) DoWork(workerCtx context.Context, worker *scheduler.Worker) {
	reqCtx, cancel := context.WithTimeout(context.Background(), worker.HSMTimeout)
	type resp struct {
		signer signerWithSignAlgorithm
		err    error
	}

	signerRespCh := make(chan resp)
	go func() {
		signer, err := w.work.pool.get(reqCtx)
		signerRespCh <- resp{signer, err}
	}()

	for {
		select {
		case <-workerCtx.Done():
			// Case 1: worker stopped either due to context cancelled or time out.
			log.Printf("%s: worker stopped", worker.String())
			cancel()
			w.sendResponse(nil)
			return
		case resp := <-signerRespCh:
			// Case 2: Received response. It could either be a time out or a signer.
			if resp.signer == nil || resp.err != nil {
				worker.TotalTimeout.Inc()
				log.Printf("%s: error fetching signer %v", worker.String(), resp.err)
				w.work.respChan <- nil
				cancel()
				return
			}
			worker.TotalProcessed.Inc()
			w.sendResponse(resp.signer)
			cancel()
			return
		case _, ok := <-w.work.respChan:
			// Case 3: Check for current state of respChan. If the client request is cancelled, the client
			// will close the respChan. In that case, we should cancel reqCtx & return to avoid extra processing.
			if !ok {
				log.Printf("%s: worker request timed out, client cancelled request", worker.String())
				cancel()
				worker.TotalTimeout.Inc()
				return
			}
		}
	}
}

// sendResponse sends the response on the respChan if the channel is not yet closed by the client.
func (w *Work) sendResponse(resp signerWithSignAlgorithm) {
	select {
	case <-w.work.respChan:
	default:
		w.work.respChan <- resp
	}
}
