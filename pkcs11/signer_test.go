package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/theparanoids/crypki"
)

const (
	defaultIdentifier = "dummy"
	badIdentifier     = "unknown"
)

// enforce signer implements CertSign interface.
var _ crypki.CertSign = (*signer)(nil)

// initMockSigner initializes a mock signer which loads credentials from local files
func initMockSigner(isBad bool) (*signer, error) {
	s := &signer{
		x509CACerts: make(map[string]*x509.Certificate),
		sPool:       make(map[string]sPool),
	}
	sp, err := newMockSignerPool(isBad)
	if err != nil {
		return nil, err
	}
	s.sPool[defaultIdentifier] = sp

	bytes, err := ioutil.ReadFile("testdata/rsa.cert.pem")
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	s.x509CACerts[defaultIdentifier] = cert
	return s, nil
}

func TestGetSSHCertSigningKey(t *testing.T) {
	t.Parallel()
	testcases := map[string]struct {
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"good-signer":    {defaultIdentifier, false, false},
		"bad-identifier": {badIdentifier, false, true},
		"bad-signer":     {defaultIdentifier, true, true},
	}
	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			signer, err := initMockSigner(tt.isBadSigner)
			if err != nil {
				t.Fatalf("unable to init mock signer: %v", err)
			}
			_, err = signer.GetSSHCertSigningKey(tt.identifier)
			if err != nil != tt.expectError {
				t.Fatalf("got err: %v, expect err: %v", err, tt.expectError)
			}
		})
	}
}

func TestSignSSHCert(t *testing.T) {
	t.Parallel()
	rsakey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("unable to generate RSA key: %v", err)
	}
	rsaPubKey, err := ssh.NewPublicKey(&rsakey.PublicKey)
	if err != nil {
		t.Fatalf("unable to create ssh RSA public key: %v", err)
	}
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate EC key: %v", err)
	}
	ecPubKey, _ := ssh.NewPublicKey(&eckey.PublicKey)
	if err != nil {
		t.Fatalf("unable to create ssh EC public key: %v", err)
	}

	exts := make(map[string]string)
	exts["permit-pty"] = ""
	exts["permit-X11-forwarding"] = ""
	exts["permit-agent-forwarding"] = ""
	exts["permit-port-forwarding"] = ""
	exts["permit-user-rc"] = ""
	opts := make(map[string]string)
	opts["source-address"] = "10.11.12.13/32"
	opts["force-command"] = "ls -l"

	now := time.Now().Unix()

	userCertRSA := &ssh.Certificate{
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"alice"},
		Key:             rsaPubKey,
		KeyId:           "foo",
		ValidBefore:     uint64(now + 1000),
		ValidAfter:      uint64(now - 1000),
		Permissions: ssh.Permissions{
			Extensions:      exts,
			CriticalOptions: opts,
		},
	}
	userCertEC := &ssh.Certificate{
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"alice"},
		Key:             ecPubKey,
		KeyId:           "foo",
		ValidBefore:     uint64(now + 1000),
		ValidAfter:      uint64(now - 1000),
		Permissions: ssh.Permissions{
			Extensions:      exts,
			CriticalOptions: opts,
		},
	}
	hostCertRSA := &ssh.Certificate{
		CertType:    ssh.HostCert,
		ValidBefore: uint64(now + 1000),
		ValidAfter:  uint64(now - 1000),
		Key:         rsaPubKey,
	}
	hostCertEC := &ssh.Certificate{
		CertType:    ssh.HostCert,
		ValidBefore: uint64(now + 1000),
		ValidAfter:  uint64(now - 1000),
		Key:         ecPubKey,
	}
	testcases := map[string]struct {
		cert        *ssh.Certificate
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"host-cert-rsa":            {hostCertRSA, defaultIdentifier, false, false},
		"host-cert-ec":             {hostCertEC, defaultIdentifier, false, false},
		"host-cert-bad-identifier": {hostCertRSA, badIdentifier, false, true},
		"host-cert-bad-signer":     {hostCertRSA, defaultIdentifier, true, true},
		"user-cert-rsa":            {userCertRSA, defaultIdentifier, false, false},
		"user-cert-ec":             {userCertEC, defaultIdentifier, false, false},
		"user-cert-bad-identifier": {userCertRSA, badIdentifier, false, true},
		"user-cert-bad-signer":     {userCertRSA, defaultIdentifier, true, true},
	}
	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			signer, err := initMockSigner(tt.isBadSigner)
			if err != nil {
				t.Fatalf("unable to init mock signer: %v", err)
			}
			data, err := signer.SignSSHCert(tt.cert, tt.identifier)
			if err != nil != tt.expectError {
				t.Fatalf("got err: %v, expect err: %v", err, tt.expectError)
			}
			if err != nil {
				return
			}
			cc := &ssh.CertChecker{SupportedCriticalOptions: []string{"force-command"}}
			pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
			if err != nil {
				t.Fatalf("unable to parse key from signed cert: %v", err)
			}
			cert, ok := pk.(*ssh.Certificate)
			if !ok {
				t.Fatal("not an ssh.Certificate type")
			}
			if err := cc.CheckCert("alice", cert); err != nil {
				t.Fatalf("check cert failed: %v", err)
			}
		})
	}
}

func TestGetX509CACert(t *testing.T) {
	t.Parallel()
	testcases := map[string]struct {
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"good-signer":    {defaultIdentifier, false, false},
		"bad-identifier": {badIdentifier, false, true},
		"bad-signer":     {defaultIdentifier, true, false},
	}
	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			signer, err := initMockSigner(tt.isBadSigner)
			if err != nil {
				t.Fatalf("unable to init mock signer: %v", err)
			}
			_, err = signer.GetX509CACert(tt.identifier)
			if err != nil != tt.expectError {
				t.Fatalf("got err: %v, expect err: %v", err, tt.expectError)
			}
		})
	}
}

func TestSignX509Cert(t *testing.T) {
	t.Parallel()
	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Foo"},
		OrganizationalUnit: []string{"FooUnit"},
		Locality:           []string{"Bar"},
		Province:           []string{"Baz"},
		CommonName:         "foo.bar.com",
	}
	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unable to generate RSA key: %v", err)
	}
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate EC key: %v", err)
	}
	ec2key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate EC key: %v", err)
	}
	certRSA := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          big.NewInt(0),
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             &rsakey.PublicKey,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		DNSNames:              []string{subject.CommonName},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certEC := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          big.NewInt(0),
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             &eckey.PublicKey,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		DNSNames:              []string{subject.CommonName},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certEC2 := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          big.NewInt(0),
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             &ec2key.PublicKey,
		SignatureAlgorithm:    x509.ECDSAWithSHA384,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		DNSNames:              []string{subject.CommonName},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	cp := x509.NewCertPool()
	caCertBytes, err := ioutil.ReadFile("testdata/rsa.cert.pem")
	if err != nil {
		t.Fatalf("unable to read CA cert: %v", err)
	}
	caCertDecoded, _ := pem.Decode(caCertBytes)
	caCert, err := x509.ParseCertificate(caCertDecoded.Bytes)
	if err != nil {
		t.Fatalf("unable to parse CA cert: %v", err)
	}
	cp.AddCert(caCert)
	timeoutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Microsecond)
	testcases := map[string]struct {
		ctx         context.Context
		cert        *x509.Certificate
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"cert-rsa-good-signer":        {context.Background(), certRSA, defaultIdentifier, false, false},
		"cert-ec-good-signer":         {context.Background(), certEC, defaultIdentifier, false, false},
		"cert-bad-identifier":         {context.Background(), certRSA, badIdentifier, false, true},
		"cert-bad-signer":             {context.Background(), certRSA, defaultIdentifier, true, true},
		"cert-ec-good-signer-timeout": {timeoutCtx, certEC2, defaultIdentifier, false, true},
	}
	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			signer, err := initMockSigner(tt.isBadSigner)
			if err != nil {
				t.Fatalf("unable to init mock signer: %v", err)
			}
			data, err := signer.SignX509Cert(tt.ctx, tt.cert, tt.identifier)
			if err != nil != tt.expectError {
				t.Fatalf("got err: %v, expect err: %v", err, tt.expectError)
			}
			if err != nil {
				return
			}
			cd, _ := pem.Decode(data)
			cert, err := x509.ParseCertificate(cd.Bytes)
			if err != nil {
				t.Fatalf("unable to parse certificate: %v", err)
			}
			if _, err := cert.Verify(x509.VerifyOptions{
				Roots:     cp,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
			}); err != nil {
				t.Fatalf("failed to verify certificate: %v", err)
			}
			if !reflect.DeepEqual(cert.Issuer.String(), caCert.Issuer.String()) {
				t.Fatalf("issuer mismatch: got %q, want: %q", cert.Issuer, caCert.Issuer.String())
			}
			if !reflect.DeepEqual(cert.Subject.String(), subject.String()) {
				t.Fatalf("subject mismatch: got %q, want: %q", cert.Subject, subject)
			}
		})
	}
	<-timeoutCtx.Done()
	cancel()
}

func TestGetBlobSigningPublicKey(t *testing.T) {
	t.Parallel()
	testcases := map[string]struct {
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"good-signer":    {defaultIdentifier, false, false},
		"bad-identifier": {badIdentifier, false, true},
		"bad-signer":     {defaultIdentifier, true, true},
	}
	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			signer, err := initMockSigner(tt.isBadSigner)
			if err != nil {
				t.Fatalf("unable to init mock signer: %v", err)
			}
			_, err = signer.GetBlobSigningPublicKey(tt.identifier)
			if err != nil != tt.expectError {
				t.Fatalf("got err: %v, expect err: %v", err, tt.expectError)
			}
		})
	}
}

func TestSignBlob(t *testing.T) {
	t.Parallel()
	blob := []byte("good")
	goodDigestSHA224 := sha256.Sum224(blob)
	goodDigestSHA256 := sha256.Sum256(blob)
	goodDigestSHA384 := sha512.Sum384(blob)
	goodDigestSHA512 := sha512.Sum512(blob)

	data, err := ioutil.ReadFile("testdata/rsa.key.pem")
	if err != nil {
		t.Fatalf("unable to read private key: %v", err)
	}
	decoded, _ := pem.Decode(data)
	key, err := x509.ParsePKCS1PrivateKey(decoded.Bytes)
	if err != nil {
		t.Fatalf("unable to parse private key: %v", err)
	}

	testcases := map[string]struct {
		digest      []byte
		opts        crypto.SignerOpts
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"good-SHA224":    {goodDigestSHA224[:], crypto.SHA224, defaultIdentifier, false, false},
		"good-SHA256":    {goodDigestSHA256[:], crypto.SHA256, defaultIdentifier, false, false},
		"good-SHA384":    {goodDigestSHA384[:], crypto.SHA384, defaultIdentifier, false, false},
		"good-SHA512":    {goodDigestSHA512[:], crypto.SHA512, defaultIdentifier, false, false},
		"bad-digest":     {[]byte("bad digest"), crypto.SHA256, defaultIdentifier, false, true},
		"bad-wrong-hash": {goodDigestSHA224[:], crypto.SHA256, defaultIdentifier, false, true},
		"bad-identifier": {goodDigestSHA224[:], crypto.SHA256, badIdentifier, false, true},
		"bad-signer":     {goodDigestSHA224[:], crypto.SHA256, defaultIdentifier, true, true},
	}
	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			signer, err := initMockSigner(tt.isBadSigner)
			if err != nil {
				t.Fatalf("unable to init mock signer: %v", err)
			}
			signature, err := signer.SignBlob(tt.digest, tt.opts, tt.identifier)
			if err != nil != tt.expectError {
				t.Fatalf("got err: %v, expect err: %v", err, tt.expectError)
			}
			if err != nil {
				return
			}

			err = rsa.VerifyPKCS1v15(&key.PublicKey, tt.opts.(crypto.Hash), tt.digest, signature)
			if err != nil {
				t.Fatalf("failed to verify certificate: %v", err)
			}
		})
	}
}
