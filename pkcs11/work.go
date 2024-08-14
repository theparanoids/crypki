// Copyright 2021 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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
	getData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, data chan []byte, errCh chan error, doneCh chan bool)
	signData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, data chan []byte, errCh chan error, doneCh chan bool)
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
	start := time.Now()
	signerResp := make(chan sInfo)
	done := make(chan bool)

	requestCtx, cancel := context.WithTimeout(context.Background(), worker.PKCS11Timeout)
	var (
		ht, pt         int64
		pStart, hStart time.Time
	)

	defer func() {
		cancel()
		tt := time.Since(start).Nanoseconds() / time.Microsecond.Nanoseconds()
		log.Printf("m=%s: ht=%d, tt=%d, pt=%d", w.work.method, ht, tt, pt)
	}()

	go func(ctx context.Context) {
		pStart = time.Now()
		signer, err := w.work.pool.get(ctx)
		select {
		case <-ctx.Done():
			// case when HSM request has timed out, we clean up signer if we were able to get it.
			w.work.pool.put(signer)
		case signerResp <- sInfo{signer, err}:
			// case when we fetched signer from the pool.
		}
	}(requestCtx)

	for {
		select {
		case <-workerCtx.Done():
			// Case 1: Worker stopped or cancelled request.
			// The client is still waiting for a response, so return on error channel.
			w.work.errChan <- errors.New("worker cancelled request")
			return
		case <-requestCtx.Done():
			// Case 2: HSM/PKCS11 request timed out.
			// The client is still waiting for a response in this case, so return on error channel.
			worker.TotalTimeout.Inc()
			w.work.errChan <- errors.New("hsm request timed out")
			return
		case <-w.work.stop:
			// Case 3: Client cancelled the request.
			// In this case we no longer need to process the signing request & we should clean up signer if assigned & return.
			worker.TotalTimeout.Inc()
			return
		case sResp := <-signerResp:
			pt = time.Since(pStart).Nanoseconds() / time.Microsecond.Nanoseconds()
			// Case 4: Received signer from signer pool. We need to sign the request & send the response. Before we send the
			// response, we should ensure client is still waiting for the response.
			if sResp.err != nil {
				worker.TotalTimeout.Inc()
				w.work.errChan <- errors.New("client request timed out, skip signing request")
				return
			}
			worker.TotalProcessed.Inc()

			hStart = time.Now()
			switch w.work.method {
			case "GetSSHCertSigningKey", "GetX509CACert", "GetBlobSigningPublicKey":
				go w.work.signerData.getData(requestCtx, sResp.signer, w.work.pool, w.work.respChan, w.work.errChan, done)
			case "SignSSHCert", "SignX509Cert", "SignBlob":
				go w.work.signerData.signData(requestCtx, sResp.signer, w.work.pool, w.work.respChan, w.work.errChan, done)
			}
		case <-done:
			ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
			// Case 5: HSM has completed the signing operation & we need to send response back to client.
			return
		}
	}
}

// getData gets X509 CA certificate.
func (s *signerX509) getData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, data chan []byte, errCh chan error, done chan bool) {
	defer pool.put(signer)
	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.x509CACert.Raw,
	})
	select {
	case <-ctx.Done():
	case data <- certBytes:
		done <- true
	}
}

// signData signs X509 certificate by using the signer fetched from the pool.
func (s *signerX509) signData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, data chan []byte, errCh chan error, done chan bool) {
	var e error
	defer func() {
		if e != nil {
			select {
			case <-ctx.Done():
			case errCh <- e:
				done <- true
			}
		}
		pool.put(signer)
	}()
	// Validate the cert request to ensure it matches the keyType and also the HSM supports the signature algo.
	if val := isValidCertRequest(s.cert, signer.signAlgorithm()); !val {
		log.Printf("signX509cert: cn=%q unsupported-sa=%q supported-sa=%d",
			s.x509CACert.Subject.CommonName, s.cert.SignatureAlgorithm.String(), signer.signAlgorithm())
		// Not a valid signature algorithm. Overwrite it with what the configured keyType supports.
		s.cert.SignatureAlgorithm = signer.signAlgorithm()
	}

	s.cert.OCSPServer = s.ocspServer
	s.cert.CRLDistributionPoints = s.crlDistribPoints

	signedCert, err := x509.CreateCertificate(rand.Reader, s.cert, s.x509CACert, s.cert.PublicKey, signer)
	if err != nil {
		e = err
		return
	}
	signedData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCert})
	select {
	case <-ctx.Done():
	case data <- signedData:
		done <- true
	}
}

// getData gets SSH certificate signing key by using the signer fetched from the pool.
func (s *signerSSH) getData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, data chan []byte, errCh chan error, done chan bool) {
	var e error
	defer func() {
		if e != nil {
			select {
			case <-ctx.Done():
			case errCh <- e:
				done <- true
			}
		}
		pool.put(signer)
	}()

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		e = fmt.Errorf("failed to create sshSigner: %v", err)
		return
	}
	select {
	case <-ctx.Done():
	case data <- ssh.MarshalAuthorizedKey(sshSigner.PublicKey()):
		done <- true
	}
}

// signData signs SSH certificate by using the signer fetched from the pool.
func (s *signerSSH) signData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, data chan []byte, errCh chan error, done chan bool) {
	var e error
	defer func() {
		if e != nil {
			select {
			case <-ctx.Done():
			case errCh <- e:
				done <- true
			}
		}
		pool.put(signer)
	}()
	if s.cert == nil {
		e = errors.New("signSSHCert: cannot sign empty cert")
		return
	}

	sshSigner, err := newAlgorithmSignerFromSigner(signer, signer.publicKeyAlgorithm(), signer.signAlgorithm())
	if err != nil {
		e = fmt.Errorf("failed to new ssh signer from signer, error :%v", err)
		return
	}
	if err := s.cert.SignCert(rand.Reader, sshSigner); err != nil {
		e = err
		return
	}
	signedData := bytes.TrimSpace(ssh.MarshalAuthorizedKey(s.cert))
	select {
	case <-ctx.Done():
	case data <- signedData:
		done <- true
	}
}

// getData gets blob signing public key by using the signer fetched from the pool.
func (s *signerBlob) getData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, data chan []byte, errCh chan error, done chan bool) {
	var e error
	defer func() {
		if e != nil {
			select {
			case <-ctx.Done():
			case errCh <- e:
				done <- true
			}
		}
		pool.put(signer)
	}()
	pk, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		e = err
		return
	}
	signedData := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pk})
	select {
	case <-ctx.Done():
	case data <- signedData:
		done <- true
	}
}

// signData signs blob data by using the signer fetched from the pool.
func (s *signerBlob) signData(ctx context.Context, signer signerWithSignAlgorithm, pool sPool, data chan []byte, errCh chan error, done chan bool) {
	var e error
	defer func() {
		if e != nil {
			select {
			case <-ctx.Done():
			case errCh <- e:
				done <- true
			}
		}
		pool.put(signer)
	}()
	if s.digest == nil {
		e = errors.New("signBlob: cannot sign empty digest")
		return
	}

	signature, err := signer.Sign(rand.Reader, s.digest, s.opts)
	if err != nil {
		e = err
		return
	}
	select {
	case <-ctx.Done():
	case data <- signature:
		done <- true
	}
}
