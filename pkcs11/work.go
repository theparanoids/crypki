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

// DoWork performs the work of fetching the signer from the pool and sending it back on the response channel.
// If the client cancels the request or times out, the worker should not wait indefinitely for getting the signer
// from the pool. We also have a PKCS11 timeout which is the maximum duration for which worker waits to fetch the
// signer from pool & cancel the client request if it exceeds that.
func (w *Work) DoWork(workerCtx context.Context, worker *scheduler.Worker) {
	type signerResponse struct {
		signer signerWithSignAlgorithm
		err    error
	}

	signerRespCh := make(chan signerResponse)
	reqCtx, cancel := context.WithTimeout(context.Background(), worker.PKCS11Timeout)
	defer cancel()
	var pt int64
	pStart := time.Now()
	go func(ctx context.Context) {
		signer, err := w.work.pool.get(ctx)
		select {
		case <-ctx.Done():
			// case when HSM request has timed out, we clean up signer if we were able to get it.
			w.work.pool.put(signer)
			return
		case signerRespCh <- signerResponse{signer, err}:
			// case when we fetched signer from the pool.
			close(signerRespCh)
		}
	}(reqCtx)

	select {
	case <-workerCtx.Done():
		// Case 1: Worker stopped or cancelled request.
		// The client is still waiting for a response, so return timeout.
		worker.TotalTimeout.Inc()
		signedData := signerWorkResponse{
			err: errors.New("worker cancelled request"),
		}
		cancel()
		w.sendResponse(signedData)
		return
	case <-reqCtx.Done():
		// Case 2: HSM request timed out.
		// The client is still waiting for a response in this case.
		worker.TotalTimeout.Inc()
		signedData := signerWorkResponse{
			err: errors.New("hsm request timed out"),
		}
		w.sendResponse(signedData)
		return
	case <-w.work.clientCtxChan:
		// Case 3: Client cancelled the request, either due to client time out or some other reason.
		// In this case we no longer need to process the signing request & we should clean up signer if assigned & return.
		worker.TotalTimeout.Inc()
		return
	case resp := <-signerRespCh:
		// Case 4: Received signer from signer pool. We need to sign the request & send the response. Before we send the
		// response, we should ensure client is still waiting for the response.
		pt = time.Since(pStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		if resp.err != nil {
			worker.TotalTimeout.Inc()
			signedData := signerWorkResponse{
				data:     nil,
				poolTime: pt,
				hsmTime:  0,
				err:      errors.New("client request timed out, skip signing request"),
			}
			w.sendResponse(signedData)
			return
		}
		worker.TotalProcessed.Inc()
		data, ht, err := w.work.signerData.signData(reqCtx, resp.signer)
		w.work.pool.put(resp.signer)
		signedData := signerWorkResponse{
			data:     data,
			poolTime: pt,
			hsmTime:  ht,
			err:      err,
		}
		w.sendResponse(signedData)
		return
	}
}

// sendResponse sends the response on the respChan if the channel is not yet closed by the client.
func (w *Work) sendResponse(resp signerWorkResponse) {
	select {
	case <-w.work.clientCtxChan:
		// case when client has already closed channel & cancelled request.
	case w.work.respChan <- resp:
		// case when client is waiting for a response from worker.
		close(w.work.respChan)
	}
}

// signData signs X509 certificate by using the signer fetched from the pool.
func (s *signerX509) signData(ctx context.Context, signer signerWithSignAlgorithm) ([]byte, int64, error) {
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
		return nil, ht, err
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCert}), ht, nil
}

// signData signs SSH certificate by using the signer fetched from the pool.
func (s *signerSSH) signData(ctx context.Context, signer signerWithSignAlgorithm) ([]byte, int64, error) {
	var ht int64
	if s.cert == nil {
		return nil, ht, errors.New("signSSHCert: cannot sign empty cert")
	}

	sshSigner, err := newAlgorithmSignerFromSigner(signer, signer.publicKeyAlgorithm(), signer.signAlgorithm())
	if err != nil {
		return nil, ht, fmt.Errorf("failed to new ssh signer from signer, error :%v", err)
	}
	// measure time taken by hsm
	hStart := time.Now()
	if err := s.cert.SignCert(rand.Reader, sshSigner); err != nil {
		ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		return nil, ht, err
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	return bytes.TrimSpace(ssh.MarshalAuthorizedKey(s.cert)), ht, nil
}

// signData signs blob data by using the signer fetched from the pool.
func (s *signerBlob) signData(ctx context.Context, signer signerWithSignAlgorithm) ([]byte, int64, error) {
	const methodName = "SignBlob"
	var ht int64
	if s.digest == nil {
		return nil, ht, fmt.Errorf("%s: cannot sign empty digest", methodName)
	}

	// measure time taken by hsm
	hStart := time.Now()
	signature, err := signer.Sign(rand.Reader, s.digest, s.opts)
	if err != nil {
		ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		return nil, ht, err
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	return signature, ht, nil
}
