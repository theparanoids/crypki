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
	"crypto"
	"crypto/rand"
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
	"github.com/theparanoids/crypki/x509cert"
)

/* Request holds information needed by the collector to fetch the request & process it.
   It also has a channel on which it waits for the response.
*/
type Request struct {
	Pool          SPool                        // Pool is a signer pool per identifier from which to fetch the signer
	Priority      proto.Priority               // Priority of the incoming request
	InsertTime    time.Time                    // InsertTime is the time when the request arrived
	RemainingTime time.Duration                // RemainingTime indicates the time remaining before either the client cancels or the request times out.
	RespChan      chan SignerWithSignAlgorithm // RespChan is the channel where the worker sends the signer once it gets it from the pool
}

// signer implements crypki.CertSign interface.
type signer struct {
	x509CACerts           map[string]*x509.Certificate
	ocspServers           map[string][]string
	crlDistributionPoints map[string][]string
	sPool                 map[string]SPool

	// login keeps all login sessions using the slot number as key.
	//
	// Note that it won't actually be used to access the tokens.
	// Instead, it is only used to log the normal user in the slots during initialization,
	// so later on when new sessions are opened to initialize sPool,
	// the sessions would be in `User Functions` state instead of `Public Session` state,
	// and the private tokens in the slots can be accessed via those sessions.
	// Ref. http://docs.oasis-open.org/pkcs11/pkcs11-ug/v2.40/cn02/pkcs11-ug-v2.40-cn02.html#_Toc406759989
	login map[uint]p11.SessionHandle
}

// NewCertSign initializes a CertSign object that interacts with PKCS11 compliant device.
func NewCertSign(ctx context.Context, pkcs11ModulePath string, keys []config.KeyConfig, requireX509CACert map[string]bool, hostname string, ips []net.IP) (crypki.CertSign, error) {
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
		sPool:                 make(map[string]SPool),
		login:                 login,
	}
	for _, key := range keys {
		pool, err := newSignerPool(p11ctx, key.SessionPoolSize, key.SlotNumber, key.KeyLabel, key.KeyType, key.SignatureAlgo)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize key with identifier %q: %v", key.Identifier, err)
		}
		s.sPool[key.Identifier] = pool
		// Initialize x509 CA cert if this key will be used for signing x509 certs.
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

func (s *signer) GetSSHCertSigningKey(ctx context.Context, keyIdentifier string) ([]byte, error) {
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signer, err := pool.Get(ctx)
	if err != nil {
		return nil, err
	}
	defer pool.Put(signer)

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create sshSigner: %v", err)
	}
	return ssh.MarshalAuthorizedKey(sshSigner.PublicKey()), nil
}

func (s *signer) SignSSHCert(ctx context.Context, cert *ssh.Certificate, keyIdentifier string) ([]byte, error) {
	const methodName = "SignSSHCert"
	start := time.Now()
	var ht, st int64
	defer func() {
		tt := time.Since(start).Nanoseconds() / time.Microsecond.Nanoseconds()
		log.Printf("m=%s: ht=%d, tt=%d, st=%d", methodName, ht, tt, st)
	}()

	if cert == nil {
		return nil, errors.New("signSSHCert: cannot sign empty cert")
	}
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	sStart := time.Now()
	signer, err := pool.Get(ctx)
	if err != nil {
		st = time.Since(sStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		return nil, errors.New("client request timed out, skip signing SSH cert")
	}
	st = time.Since(sStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	defer pool.Put(signer)

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to new ssh signer from signer, error :%v", err)
	}
	// measure time taken by hsm
	hStart := time.Now()
	if err := cert.SignCert(rand.Reader, sshSigner); err != nil {
		ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		return nil, err
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	return bytes.TrimSpace(ssh.MarshalAuthorizedKey(cert)), nil
}

func (s *signer) GetX509CACert(ctx context.Context, keyIdentifier string) ([]byte, error) {
	cert, ok := s.x509CACerts[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unable to find CA cert for key identifier %q", keyIdentifier)
	}
	certBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return certBytes, nil
}

func (s *signer) SignX509Cert(ctx context.Context, cert *x509.Certificate, keyIdentifier string) ([]byte, error) {
	const methodName = "SignX509Cert"
	start := time.Now()
	var ht, st int64
	defer func() {
		xt := time.Since(start).Nanoseconds() / time.Microsecond.Nanoseconds()
		log.Printf("m=%s: ht=%d, xt=%d st=%d", methodName, ht, xt, st)
	}()

	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	sStart := time.Now()
	signer, err := pool.Get(ctx)
	if err != nil {
		st = time.Since(sStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		return nil, errors.New("client request timed out, skip signing X509 cert")
	}
	st = time.Since(sStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	defer pool.Put(signer)
	// Validate the cert request to ensure it matches the keyType and also the HSM supports the signature algo.
	if val := isValidCertRequest(cert, signer.SignAlgorithm()); !val {
		log.Printf("signX509cert: cn=%q unsupported-sa=%q supported-sa=%d",
			s.x509CACerts[keyIdentifier].Subject.CommonName, cert.SignatureAlgorithm.String(), signer.SignAlgorithm())
		// Not a valid signature algorithm. Overwrite it with what the configured keyType supports.
		cert.SignatureAlgorithm = x509cert.GetSignatureAlgorithm(signer.SignAlgorithm())
	}

	cert.OCSPServer = s.ocspServers[keyIdentifier]
	cert.CRLDistributionPoints = s.crlDistributionPoints[keyIdentifier]

	// measure time taken by hsm
	hStart := time.Now()
	signedCert, err := x509.CreateCertificate(rand.Reader, cert, s.x509CACerts[keyIdentifier], cert.PublicKey, signer)
	if err != nil {
		ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		return nil, err
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: signedCert}), nil
}

func (s *signer) GetBlobSigningPublicKey(ctx context.Context, keyIdentifier string) ([]byte, error) {
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signer, err := pool.Get(ctx)
	if err != nil {
		return nil, err
	}
	defer pool.Put(signer)
	pk, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, err
	}
	b := &pem.Block{Type: "PUBLIC KEY", Bytes: pk}
	return pem.EncodeToMemory(b), nil
}

func (s *signer) SignBlob(ctx context.Context, digest []byte, opts crypto.SignerOpts, keyIdentifier string) ([]byte, error) {
	const methodName = "SignBlob"
	start := time.Now()
	var ht int64
	defer func() {
		tt := time.Since(start).Nanoseconds() / time.Microsecond.Nanoseconds()
		log.Printf("m=%s: ht=%d, tt=%d", methodName, ht, tt)
	}()

	if digest == nil {
		return nil, fmt.Errorf("%s: cannot sign empty digest", methodName)
	}
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signer, err := pool.Get(ctx)
	if err != nil {
		return nil, err
	}
	defer pool.Put(signer)

	// measure time taken by hsm
	hStart := time.Now()
	signature, err := signer.Sign(rand.Reader, digest, opts)
	if err != nil {
		ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
		return nil, err
	}
	ht = time.Since(hStart).Nanoseconds() / time.Microsecond.Nanoseconds()
	return signature, nil
}

// getX509CACert reads and returns x509 CA certificate from X509CACertLocation.
// If the certificate is not valid, and CreateCACertIfNotExist is true, a new CA
// certificate will be generated based on the config, and wrote to X509CACertLocation.
func getX509CACert(ctx context.Context, key config.KeyConfig, pool SPool, hostname string, ips []net.IP) (*x509.Certificate, error) {
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
		return nil, errors.New("unable to Get x509 CA certificate, but CreateCACertIfNotExist is set to false")
	}
	// Create x509 CA cert.
	signer, err := pool.Get(ctx)
	if err != nil {
		return nil, err
	}
	defer pool.Put(signer)

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

	out, err := x509cert.GenCACert(caConfig, signer, hostname, ips, signer.PublicKeyAlgorithm(), signer.SignAlgorithm())
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

func isValidCertRequest(cert *x509.Certificate, sa crypki.SignatureAlgorithm) bool {
	return cert.SignatureAlgorithm == x509cert.GetSignatureAlgorithm(sa)
}
