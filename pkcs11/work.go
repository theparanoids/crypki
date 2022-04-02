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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/theparanoids/crypki/server/scheduler"
)

type Work struct {
	scheduler.DoWorker

	work *Request // workChan is a channel which has a request enqueue for the worker to work on.
}

// signerMetadata is an interface for the worker to get the work done.
type signerMetadata interface {
	signData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, signedDataCh chan Response)
}

// DoWork performs the work of fetching the signer from the pool and sending it back on the response channel.
// If the client cancels the request or times out, the worker should not wait indefinitely for getting the signer
// from the pool. We also have a PKCS11 timeout which is the maximum duration for which worker waits to fetch the
// signer from pool & cancel the client request if it exceeds that.
func (w *Work) DoWork(workerCtx context.Context, worker *scheduler.Worker) {
	type sInfo struct {
		signer signerWithSignAlgorithm
		err    error
	}
	var poolTime int64

	signerResp := make(chan sInfo)
	dataCh := make(chan Response)

	reqCtx, cancel := context.WithTimeout(context.Background(), worker.PKCS11Timeout)
	defer cancel()
	pStart := time.Now()
	go func(ctx context.Context) {
		signer, err := w.work.pool.get(ctx)
		select {
		case <-ctx.Done():
			// case when HSM request has timed out, we clean up signer if we were able to get it.
			w.work.pool.put(signer)
		case signerResp <- sInfo{signer, err}:
			// case when we fetched signer from the pool.
		}
	}(reqCtx)

	for {
		select {
		case <-workerCtx.Done():
			// Case 1: Worker stopped or cancelled request.
			// The client is still waiting for a response, so return timeout.
			worker.TotalTimeout.Inc()
			cancel()
			signedData := Response{
				err: errors.New("worker cancelled request"),
			}
			w.sendResponse(signedData)
			return
		case <-reqCtx.Done():
			// Case 2: HSM/PKCS11 request timed out.
			// The client is still waiting for a response in this case.
			worker.TotalTimeout.Inc()
			signedData := Response{
				err: errors.New("hsm request timed out"),
			}
			w.sendResponse(signedData)
			return
		case <-w.work.stop:
			// Case 3: Client cancelled the request.
			// In this case we no longer need to process the signing request & we should clean up signer if assigned & return.
			worker.TotalTimeout.Inc()
			cancel()
			return
		case sResp := <-signerResp:
			// Case 4: Received signer from signer pool. We need to sign the request & send the response. Before we send the
			// response, we should ensure client is still waiting for the response.
			poolTime = time.Since(pStart).Nanoseconds() / time.Microsecond.Nanoseconds()
			if sResp.err != nil {
				worker.TotalTimeout.Inc()
				signedData := Response{
					poolTime: poolTime,
					err:      errors.New("client request timed out, skip signing request"),
				}
				w.sendResponse(signedData)
				return
			}
			worker.TotalProcessed.Inc()
			go w.work.signerData.signData(reqCtx, sResp.signer, w.work.pool, dataCh)
		case signedData := <-dataCh:
			// Case 5: HSM has completed the signing operation & we need to send response back to client.
			w.sendResponse(signedData)
			return
		}
	}
}

// sendResponse sends the response on the respChan if the channel is not yet closed by the client.
func (w *Work) sendResponse(resp Response) {
	w.work.respChan <- resp
	// case when client is waiting for a response from worker.
	// close(w.work.respChan)
}

// signData signs X509 certificate by using the signer fetched from the pool.
func (s *signerX509) signData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, signedDataCh chan Response) {
	defer pool.put(signer)
	// Validate the cert request to ensure it matches the keyType and also the HSM supports the signature algo.
	if val := isValidCertRequest(s.cert, signer.signAlgorithm()); !val {
		log.Printf("signX509cert: cn=%q unsupported-sa=%q supported-sa=%d",
			s.x509CACert.Subject.CommonName, s.cert.SignatureAlgorithm.String(), signer.signAlgorithm())
		// Not a valid signature algorithm. Overwrite it with what the configured keyType supports.
		s.cert.SignatureAlgorithm = signer.signAlgorithm()
	}

	s.cert.OCSPServer = s.ocspServer
	s.cert.CRLDistributionPoints = s.crlDistribPoints

	// measure time taken by hsm
	var ht int64
	hStart := time.Now()
	signedCert, err := x509.CreateCertificate(rand.Reader, s.cert, s.x509CACert, s.cert.PublicKey, signer)
	if err != nil {
		ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		signedDataCh <- Response{hsmTime: ht, err: err}
		return
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	select {
	case <-ctx.Done():
	case signedDataCh <- Response{data: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCert}), hsmTime: ht}:
	}
}

// signData signs SSH certificate by using the signer fetched from the pool.
func (s *signerSSH) signData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, signedDataCh chan Response) {
	defer pool.put(signer)
	var ht int64
	if s.cert == nil {
		signedDataCh <- Response{err: errors.New("signSSHCert: cannot sign empty cert")}
		return
	}

	sshSigner, err := newAlgorithmSignerFromSigner(signer, signer.publicKeyAlgorithm(), signer.signAlgorithm())
	if err != nil {
		signedDataCh <- Response{err: fmt.Errorf("failed to new ssh signer from signer, error :%v", err)}
		return
	}
	// measure time taken by hsm
	hStart := time.Now()
	if err := s.cert.SignCert(rand.Reader, sshSigner); err != nil {
		ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		signedDataCh <- Response{hsmTime: ht, err: err}
		return
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	select {
	case <-ctx.Done():
	case signedDataCh <- Response{data: bytes.TrimSpace(ssh.MarshalAuthorizedKey(s.cert)), hsmTime: ht}:
	}
}

// signData signs blob data by using the signer fetched from the pool.
func (s *signerBlob) signData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, signedDataCh chan Response) {
	defer pool.put(signer)
	var ht int64
	if s.digest == nil {
		signedDataCh <- Response{err: fmt.Errorf("signBlob: cannot sign empty digest")}
		return
	}

	// measure time taken by hsm
	hStart := time.Now()
	signature, err := signer.Sign(rand.Reader, s.digest, s.opts)
	if err != nil {
		ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		signedDataCh <- Response{hsmTime: ht, err: err}
		return
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	select {
	case <-ctx.Done():
	case signedDataCh <- Response{data: signature, hsmTime: ht}:
	}
}
