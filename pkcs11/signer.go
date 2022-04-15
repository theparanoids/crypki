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
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	p11 "github.com/miekg/pkcs11"
	"golang.org/x/crypto/ssh"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/scheduler"
	"github.com/theparanoids/crypki/x509cert"
)

// Request holds information needed by the collector to fetch the request & process it.
// It has multiple channels, one for response & other to notify the worker if the client request times out to stop
// processing any request from the client.
type Request struct {
	pool       sPool          // pool is a signer pool per identifier from which to fetch the signer
	method     string         // method is type of method the worker needs to call based on the request
	stop       chan bool      // stop is the channel which is closed when the consumer/client times out or cancels request
	signerData signerMetadata // signerMetadata is an interface which each request can override & use to sign data
	respChan   chan []byte    // respChan is the channel where the worker sends the signed data
	errChan    chan error     // errChan is channel where the worker sends an error in case it is not able to sign the request
}

type signerX509 struct {
	cert             *x509.Certificate
	identifier       string
	ocspServer       []string
	crlDistribPoints []string
	x509CACert       *x509.Certificate
}

type signerSSH struct {
	cert *ssh.Certificate
}

type signerBlob struct {
	digest []byte
	opts   crypto.SignerOpts
}

// signer implements crypki.CertSign interface.
type signer struct {
	x509CACerts           map[string]*x509.Certificate
	ocspServers           map[string][]string
	crlDistributionPoints map[string][]string
	sPool                 map[string]sPool

	// login keeps all login sessions using the slot number as key.
	//
	// Note that it won't actually be used to access the tokens.
	// Instead, it is only used to log the normal user in the slots during initialization,
	// so later on when new sessions are opened to initialize sPool,
	// the sessions would be in `User Functions` state instead of `Public Session` state,
	// and the private tokens in the slots can be accessed via those sessions.
	// Ref. http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/cn02/pkcs11-ug-v2.40-cn02.html#_Toc406759989
	login          map[uint]p11.SessionHandle
	requestTimeout uint
}

func getSignerData(ctx context.Context, requestChan chan scheduler.Request, pool sPool, priority proto.Priority, method string, signRequest signerMetadata) (data []byte, err error) {
	respChan := make(chan []byte)
	errChan := make(chan error)
	stop := make(chan bool)
	req := &Request{
		pool:       pool,
		signerData: signRequest,
		method:     method,
		stop:       stop,
		respChan:   respChan,
		errChan:    errChan,
	}
	if priority == proto.Priority_Unspecified_priority {
		// If priority is unspecified, treat the request as high priority.
		priority = proto.Priority_High
	}
	select {
	case requestChan <- scheduler.Request{Priority: priority, DoWorker: &Work{work: req}}:
	case <-ctx.Done():
		// channel is closed.
		// This should ideally not happen but in order to avoid a blocking call we add this check in place.
		return nil, errors.New("request channel is closed, cannot fetch signer")
	}

	select {
	case err := <-errChan:
		return nil, err
	case resp := <-respChan:
		return resp, nil
	case <-ctx.Done():
		close(stop)
		return nil, ctx.Err()
	}
}

// NewCertSign initializes a CertSign object that interacts with PKCS11 compliant device.
func NewCertSign(ctx context.Context, pkcs11ModulePath string, keys []config.KeyConfig, requireX509CACert map[string]bool, hostname string, ips []net.IP, requestTimeout uint) (crypki.CertSign, error) {
	p11ctx, err := initPKCS11Context(pkcs11ModulePath)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize PKCS11 context: %v", err)
	}

	for idx, key := range keys {
		if key.TokenLabel != "" {
			if keys[idx].SlotNumber, err = findSlotNumber(p11ctx, key.TokenLabel); err != nil {
				return nil, fmt.Errorf("unable to initialize key with identifier %q: %v", key.Identifier, err)
			}
		}
	}
	err = config.ValidatePinIntegrity(keys)
	if err != nil {
		return nil, err
	}

	login, err := getLoginSessions(p11ctx, keys)
	if err != nil {
		return nil, fmt.Errorf("failed to create login sessions, err: %v", err)
	}

	s := &signer{
		x509CACerts:           make(map[string]*x509.Certificate),
		ocspServers:           make(map[string][]string),
		crlDistributionPoints: make(map[string][]string),
		sPool:                 make(map[string]sPool),
		login:                 login,
		requestTimeout:        requestTimeout,
	}
	for _, key := range keys {
		pool, err := newSignerPool(p11ctx, key.SessionPoolSize, key.SlotNumber, key.KeyLabel, key.KeyType, key.SignatureAlgo)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize key with identifier %q: %v", key.Identifier, err)
		}
		s.sPool[key.Identifier] = pool
		// initialize x509 CA cert if this key will be used for signing x509 certs.
		if requireX509CACert[key.Identifier] {
			cert, err := getX509CACert(ctx, key, pool, hostname, ips)
			if err != nil {
				log.Fatalf("failed to get x509 CA cert for key with identifier %q, err: %v", key.Identifier, err)
			}
			s.x509CACerts[key.Identifier] = cert
			log.Printf("x509 CA cert loaded for key %q", key.Identifier)
		}
		s.ocspServers[key.Identifier] = key.OCSPServers
		s.crlDistributionPoints[key.Identifier] = key.CRLDistributionPoints
	}
	return s, nil
}

func (s *signer) GetSSHCertSigningKey(ctx context.Context, reqChan chan scheduler.Request, keyIdentifier string) ([]byte, error) {
	const methodName = "GetSSHCertSigningKey"
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signRequest := &signerSSH{}
	return getSignerData(ctx, reqChan, pool, proto.Priority_High, methodName, signRequest)
}

func (s *signer) SignSSHCert(ctx context.Context, reqChan chan scheduler.Request, cert *ssh.Certificate, keyIdentifier string, priority proto.Priority) ([]byte, error) {
	const methodName = "SignSSHCert"
	if cert == nil {
		return nil, errors.New("signSSHCert: cannot sign empty cert")
	}
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}

	signRequest := &signerSSH{cert: cert}
	return getSignerData(ctx, reqChan, pool, priority, methodName, signRequest)
}

func (s *signer) GetX509CACert(ctx context.Context, reqChan chan scheduler.Request, keyIdentifier string) ([]byte, error) {
	const methodName = "GetSSHCertSigningKey"
	cert, ok := s.x509CACerts[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unable to find CA cert for key identifier %q", keyIdentifier)
	}
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signRequest := &signerX509{
		cert:       cert,
		identifier: keyIdentifier,
		x509CACert: s.x509CACerts[keyIdentifier],
	}
	return getSignerData(ctx, reqChan, pool, proto.Priority_High, methodName, signRequest)
}

func (s *signer) SignX509Cert(ctx context.Context, reqChan chan scheduler.Request, cert *x509.Certificate, keyIdentifier string, priority proto.Priority) ([]byte, error) {
	const methodName = "SignX509Cert"

	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signRequest := &signerX509{cert: cert,
		identifier:       keyIdentifier,
		ocspServer:       s.ocspServers[keyIdentifier],
		crlDistribPoints: s.crlDistributionPoints[keyIdentifier],
		x509CACert:       s.x509CACerts[keyIdentifier],
	}
	return getSignerData(ctx, reqChan, pool, priority, methodName, signRequest)
}

func (s *signer) GetBlobSigningPublicKey(ctx context.Context, reqChan chan scheduler.Request, keyIdentifier string) ([]byte, error) {
	const methodName = "GetBlobSigningPublicKey"
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signRequest := &signerBlob{}
	return getSignerData(ctx, reqChan, pool, proto.Priority_High, methodName, signRequest)
}

func (s *signer) SignBlob(ctx context.Context, reqChan chan scheduler.Request, digest []byte, opts crypto.SignerOpts, keyIdentifier string, priority proto.Priority) ([]byte, error) {
	const methodName = "SignBlob"

	if digest == nil {
		return nil, fmt.Errorf("%s: cannot sign empty digest", methodName)
	}
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signRequest := &signerBlob{digest: digest, opts: opts}
	return getSignerData(ctx, reqChan, pool, priority, methodName, signRequest)
}

// getX509CACert reads and returns x509 CA certificate from X509CACertLocation.
// If the certificate is not valid, and CreateCACertIfNotExist is true, a new CA
// certificate will be generated based on the config, and wrote to X509CACertLocation.
func getX509CACert(ctx context.Context, key config.KeyConfig, pool sPool, hostname string, ips []net.IP) (*x509.Certificate, error) {
	// Try parse certificate in the given location.
	if certBytes, err := os.ReadFile(key.X509CACertLocation); err == nil {
		block, _ := pem.Decode(certBytes)
		if cert, err := x509.ParseCertificate(block.Bytes); err != nil {
			log.Printf("unable to parse x509 certificate: %v", err)
		} else if time.Now().After(cert.NotAfter) || time.Now().Before(cert.NotBefore) {
			log.Printf("invalid x509 CA certificate: valid between %s and %s", cert.NotBefore.Format(time.RFC822), cert.NotAfter.Format(time.RFC822))
		} else {
			// x509 CA certificate is good. return it.
			return cert, nil
		}
	} else {
		log.Printf("unable to read file %s: %v", key.X509CACertLocation, err)
	}
	if !key.CreateCACertIfNotExist {
		return nil, errors.New("unable to get x509 CA certificate, but CreateCACertIfNotExist is set to false")
	}
	// Create x509 CA cert.
	signer, err := pool.get(ctx)
	if err != nil {
		return nil, err
	}
	defer pool.put(signer)

	caConfig := &crypki.CAConfig{
		Country:            key.Country,
		State:              key.State,
		Locality:           key.Locality,
		Organization:       key.Organization,
		OrganizationalUnit: key.OrganizationalUnit,
		CommonName:         key.CommonName,
		ValidityPeriod:     key.ValidityPeriod,
	}
	caConfig.LoadDefaults()

	out, err := x509cert.GenCACert(caConfig, signer, hostname, ips, signer.publicKeyAlgorithm(), signer.signAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("unable to generate x509 CA certificate: %v", err)
	}
	if err := os.WriteFile(key.X509CACertLocation, out, 0644); err != nil {
		log.Printf("new CA cert generated, but unable to write to file %s: %v", key.X509CACertLocation, err)
		log.Printf("cert generated: %q", string(out))
	} else {
		log.Printf("new x509 CA cert written to %s", key.X509CACertLocation)
	}
	cd, _ := pem.Decode(out)
	cert, _ := x509.ParseCertificate(cd.Bytes)
	return cert, nil
}

func isValidCertRequest(cert *x509.Certificate, sa x509.SignatureAlgorithm) bool {
	return cert.SignatureAlgorithm == sa
}
