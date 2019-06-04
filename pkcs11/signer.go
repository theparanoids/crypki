package pkcs11

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"github.com/yahoo/crypki"
	"github.com/yahoo/crypki/config"
	"github.com/yahoo/crypki/x509cert"
	"golang.org/x/crypto/ssh"
)

// signer implements crypki.CertSign interface.
type signer struct {
	x509CACerts map[string]*x509.Certificate
	sPool       map[string]sPool
}

// NewCertSign initializes a CertSign object that interacts with PKCS11 compliant device.
func NewCertSign(pkcs11ModulePath string, keys []config.KeyConfig, requireX509CACert map[string]bool, hostname string, ips []net.IP) (crypki.CertSign, error) {
	p11ctx, err := initPKCS11Context(pkcs11ModulePath)
	if err != nil {
		return nil, fmt.Errorf("unable to initialize PKCS11 context: %v", err)
	}
	s := &signer{
		x509CACerts: make(map[string]*x509.Certificate),
		sPool:       make(map[string]sPool),
	}
	for _, key := range keys {
		pin, err := getUserPin(key.UserPinPath)
		if err != nil {
			return nil, fmt.Errorf("unable to read user pin for key with identifier %q, pin path: %v, err: %v", key.Identifier, key.UserPinPath, err)
		}
		pool, err := newSignerPool(p11ctx, key.SessionPoolSize, key.SlotNumber, key.KeyLabel, pin, key.KeyType)
		if err != nil {
			return nil, fmt.Errorf("unable to initialize key with identifier %q: %v", key.Identifier, err)
		}
		s.sPool[key.Identifier] = pool
		// Initialize x509 CA cert if this key will be used for signing x509 certs.
		if requireX509CACert[key.Identifier] {
			cert, err := getX509CACert(key, pool, hostname, ips)
			if err != nil {
				log.Fatalf("failed to get x509 CA cert for key %q: %v", key.Identifier, err)
			}
			s.x509CACerts[key.Identifier] = cert
			log.Printf("x509 CA cert loaded for key %q", key.Identifier)
		}
	}
	return s, nil
}

func (s *signer) GetSSHCertSigningKey(keyIdentifier string) ([]byte, error) {
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signer := pool.get()
	defer pool.put(signer)

	sshSigner, err := ssh.NewSignerFromSigner(signer)
	if err != nil {
		return nil, fmt.Errorf("failed to create sshSigner: %v", err)
	}
	return ssh.MarshalAuthorizedKey(sshSigner.PublicKey()), nil
}

func (s *signer) SignSSHCert(cert *ssh.Certificate, keyIdentifier string) ([]byte, error) {
	const methodName = "SignSSHCert"
	start := time.Now()
	var ht int64
	defer func() {
		tt := time.Since(start).Nanoseconds() / time.Microsecond.Nanoseconds()
		log.Printf("m=%s: ht=%d, tt=%d", methodName, ht, tt)
	}()

	if cert == nil {
		return nil, errors.New("%s: cannot sign empty cert")
	}
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signer := pool.get()
	defer pool.put(signer)

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

func (s *signer) GetX509CACert(keyIdentifier string) ([]byte, error) {
	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signer := pool.get()
	defer pool.put(signer)

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

func (s *signer) SignX509Cert(cert *x509.Certificate, keyIdentifier string) ([]byte, error) {
	const methodName = "SignX509Cert"
	start := time.Now()
	var ht int64
	defer func() {
		xt := time.Since(start).Nanoseconds() / time.Microsecond.Nanoseconds()
		log.Printf("m=%s: ht=%d, xt=%d", methodName, ht, xt)
	}()

	pool, ok := s.sPool[keyIdentifier]
	if !ok {
		return nil, fmt.Errorf("unknown key identifier %q", keyIdentifier)
	}
	signer := pool.get()
	defer pool.put(signer)

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

func (s *signer) GetBlobSigningPublicKey(keyIdentifier string) ([]byte, error) {
	return nil, errors.New("not implemented")
}
func (s *signer) Sign(digest []byte, opts crypto.SignerOpts, keyIdentifier string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

// getX509CACert reads and returns x509 CA certificate from X509CACertLocation.
// If the certificate is not valid, and CreateCACertIfNotExist is true, a new CA
// certificate will be generated based on the config, and wrote to X509CACertLocation.
func getX509CACert(key config.KeyConfig, pool sPool, hostname string, ips []net.IP) (*x509.Certificate, error) {
	// Try parse certificate in the given location.
	if certBytes, err := ioutil.ReadFile(key.X509CACertLocation); err == nil {
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
	signer := pool.get()
	defer pool.put(signer)

	out, err := x509cert.GenCACert(&crypki.CAConfig{
		Country:            key.Country,
		State:              key.State,
		Locality:           key.Locality,
		Organization:       key.Organization,
		OrganizationalUnit: key.OrganizationalUnit,
		CommonName:         key.CommonName,
	}, signer, hostname, ips, signer.signAlgorithm())
	if err != nil {
		return nil, fmt.Errorf("unable to generate x509 CA certificate: %v", err)
	}
	if err := ioutil.WriteFile(key.X509CACertLocation, out, 0644); err != nil {
		log.Printf("new CA cert generated, but unable to write to file %s: %v", key.X509CACertLocation, err)
		log.Printf("cert generated: %q", string(out))
	} else {
		log.Printf("new x509 CA cert written to %s", key.X509CACertLocation)
	}
	cd, _ := pem.Decode(out)
	cert, _ := x509.ParseCertificate(cd.Bytes)
	return cert, nil
}

func getUserPin(pinFilePath string) (string, error) {
	userPin, err := ioutil.ReadFile(pinFilePath)
	if err != nil {
		return "", errors.New("Failed to open pin file: " + err.Error())
	}
	userPinStr := string(userPin)
	userPinStr = strings.TrimSpace(userPinStr) // for removing trailing '/n'
	return userPinStr, nil
}
