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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/scheduler"
)

const (
	defaultIdentifier = "dummy"
	badIdentifier     = "unknown"
	timeout           = 100 * time.Millisecond
)

// enforce signer implements CertSign interface.
var _ crypki.CertSign = (*signer)(nil)

// createCAKeysAndCert generates key pairs and the corresponding x509 certificate for unit tests CA based on key type.
func createCAKeysAndCert(keyType x509.PublicKeyAlgorithm) (priv crypto.Signer, cert *x509.Certificate, err error) {
	var pkAlgo x509.PublicKeyAlgorithm
	var sigAlgo x509.SignatureAlgorithm
	switch keyType {
	case x509.ECDSA:
		pkAlgo = x509.ECDSA
		sigAlgo = x509.ECDSAWithSHA256
		priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case x509.RSA:
		fallthrough
	default:
		pkAlgo = x509.RSA
		sigAlgo = x509.SHA256WithRSA
		priv, err = rsa.GenerateKey(rand.Reader, 2048)
	}
	if err != nil {
		return nil, nil, err
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Oath Inc."},
			Locality:     []string{"Sunnyvale"},
			CommonName:   "testca.cameo.ouroath.com",
		},
		SerialNumber:          big.NewInt(1),
		PublicKeyAlgorithm:    pkAlgo,
		PublicKey:             priv.Public(),
		SignatureAlgorithm:    sigAlgo,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, nil, err
	}

	cert, err = x509.ParseCertificate(certBytes)
	return
}

// initMockSigner initializes a mock signer.
func initMockSigner(keyType x509.PublicKeyAlgorithm, priv crypto.Signer, cert *x509.Certificate, isBad bool, sleepTime time.Duration, requestTimeout uint) *signer {
	s := &signer{
		x509CACerts: make(map[string]*x509.Certificate),
		sPool:       make(map[string]sPool),
	}

	sp := newMockSignerPool(isBad, keyType, priv)
	s.sPool[defaultIdentifier] = sp
	s.x509CACerts[defaultIdentifier] = cert
	s.requestTimeout = requestTimeout
	time.Sleep(sleepTime)
	return s
}

func dummyScheduler(ctx context.Context, reqChan chan scheduler.Request) {
	for {
		req := <-reqChan
		go func() {
			// create worker with different priorities
			worker := &scheduler.Worker{ID: 1, Priority: req.Priority, Quit: make(chan struct{}), PKCS11Timeout: 1 * time.Second}
			req.DoWorker.DoWork(ctx, worker)
		}()
	}
}

func TestGetSSHCertSigningKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	testcases := map[string]struct {
		ctx         context.Context
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"good-signer":         {ctx, defaultIdentifier, false, false},
		"bad-identifier":      {ctx, badIdentifier, false, true},
		"bad-signer":          {ctx, defaultIdentifier, true, true},
		"bad-request-timeout": {timeoutCtx, defaultIdentifier, false, true},
	}
	for label, tt := range testcases {
		label, tt := label, tt
		t.Run(label, func(t *testing.T) {
			caPriv, caCert, err := createCAKeysAndCert(x509.RSA)
			if err != nil {
				t.Fatalf("unable to create CA keys and certificate: %v", err)
			}
			signer := initMockSigner(x509.RSA, caPriv, caCert, tt.isBadSigner, timeout, 10)
			_, err = signer.GetSSHCertSigningKey(tt.ctx, tt.identifier)
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
	ctx := context.Background()
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	reqChan := make(chan scheduler.Request)
	go dummyScheduler(ctx, reqChan)
	testcases := map[string]struct {
		ctx                   context.Context
		cert                  *ssh.Certificate
		keyType               x509.PublicKeyAlgorithm
		identifier            string
		priority              proto.Priority
		isBadSigner           bool
		expectError           bool
		expectedSignatureAlgo string
	}{
		"host-cert-rsa":             {ctx, hostCertRSA, x509.RSA, defaultIdentifier, proto.Priority_Low, false, false, ssh.SigAlgoRSASHA2256},
		"host-cert-ec":              {ctx, hostCertEC, x509.ECDSA, defaultIdentifier, proto.Priority_Medium, false, false, ssh.KeyAlgoECDSA256},
		"host-cert-bad-signer":      {ctx, hostCertRSA, x509.RSA, defaultIdentifier, proto.Priority_Low, true, true, ""},
		"user-cert-rsa":             {ctx, userCertRSA, x509.RSA, defaultIdentifier, proto.Priority_Unspecified_priority, false, false, ssh.SigAlgoRSASHA2256},
		"user-cert-ec":              {ctx, userCertEC, x509.ECDSA, defaultIdentifier, proto.Priority_Medium, false, false, ssh.KeyAlgoECDSA256},
		"user-cert-bad-identifier":  {ctx, userCertRSA, x509.RSA, badIdentifier, proto.Priority_High, false, true, ""},
		"user-cert-bad-signer":      {ctx, userCertRSA, x509.RSA, defaultIdentifier, proto.Priority_Low, true, true, ""},
		"user-cert-request-timeout": {timeoutCtx, userCertRSA, x509.RSA, defaultIdentifier, proto.Priority_Low, false, true, ""},
	}
	for label, tt := range testcases {
		label, tt := label, tt
		t.Run(label, func(t *testing.T) {
			caPriv, caCert, err := createCAKeysAndCert(tt.keyType)
			if err != nil {
				t.Fatalf("unable to create CA keys and certificate: %v", err)
			}
			signer := initMockSigner(tt.keyType, caPriv, caCert, tt.isBadSigner, timeout, 10)
			data, err := signer.SignSSHCert(tt.ctx, reqChan, tt.cert, tt.identifier, tt.priority)
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
			if tt.expectedSignatureAlgo != cert.Signature.Format {
				t.Fatalf("mismatch signature algorithm, got %s want %s", cert.Signature.Format, tt.expectedSignatureAlgo)
			}
		})
	}
}

func TestGetX509CACert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
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
		label, tt := label, tt
		t.Run(label, func(t *testing.T) {
			caPriv, caCert, err := createCAKeysAndCert(x509.RSA)
			if err != nil {
				t.Fatalf("unable to create CA keys and certificate: %v", err)
			}
			signer := initMockSigner(x509.RSA, caPriv, caCert, tt.isBadSigner, timeout, 10)
			_, err = signer.GetX509CACert(ctx, tt.identifier)
			if err != nil != tt.expectError {
				t.Fatalf("got err: %v, expect err: %v", err, tt.expectError)
			}
		})
	}
}

func TestSignX509RSACert(t *testing.T) {
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

	caPriv, caCert, err := createCAKeysAndCert(x509.RSA)
	if err != nil {
		t.Fatalf("unable to create CA keys and certificate: %v", err)
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)

	ctx, cnc := context.WithTimeout(context.Background(), 1*time.Second)
	defer cnc()
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	reqChan := make(chan scheduler.Request)
	testcases := map[string]struct {
		ctx         context.Context
		cert        *x509.Certificate
		identifier  string
		priority    proto.Priority
		isBadSigner bool
		expectError bool
	}{
		"cert-rsa-good-signer":   {ctx, certRSA, defaultIdentifier, proto.Priority_High, false, false},
		"cert-bad-identifier":    {ctx, certRSA, badIdentifier, proto.Priority_Medium, false, true},
		"cert-bad-signer":        {ctx, certRSA, defaultIdentifier, proto.Priority_Low, true, true},
		"cert-request-cancelled": {cancelCtx, certRSA, defaultIdentifier, proto.Priority_Unspecified_priority, false, true},
	}
	go dummyScheduler(ctx, reqChan)
	for label, tt := range testcases {
		label, tt := label, tt
		t.Run(label, func(t *testing.T) {
			signer := initMockSigner(x509.RSA, caPriv, caCert, tt.isBadSigner, timeout, 10)
			if tt.ctx == cancelCtx {
				cancel()
			}
			data, err := signer.SignX509Cert(tt.ctx, reqChan, tt.cert, tt.identifier, tt.priority)
			if err != nil != tt.expectError {
				t.Fatalf("%s: got err: %v, expect err: %v", label, err, tt.expectError)
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
}

func TestSignX509ECCert(t *testing.T) {
	t.Parallel()
	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Foo"},
		OrganizationalUnit: []string{"FooUnit"},
		Locality:           []string{"Bar"},
		Province:           []string{"Baz"},
		CommonName:         "foo.bar.com",
	}
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate EC key: %v", err)
	}
	certEC := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          big.NewInt(0),
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             &eckey.PublicKey,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		DNSNames:              []string{subject.CommonName},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	caPriv, caCert, err := createCAKeysAndCert(x509.ECDSA)
	if err != nil {
		t.Fatalf("unable to create CA keys and certificate: %v", err)
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)

	ctx, cnc := context.WithTimeout(context.Background(), 1*time.Second)
	defer cnc()
	reqChan := make(chan scheduler.Request)
	testcases := map[string]struct {
		ctx         context.Context
		cert        *x509.Certificate
		identifier  string
		priority    proto.Priority
		isBadSigner bool
		expectError bool
	}{
		"cert-ec-good-signer":       {ctx, certEC, defaultIdentifier, proto.Priority_Unspecified_priority, false, false},
		"cert-ec-bad-identifier":    {ctx, certEC, badIdentifier, proto.Priority_Medium, false, true},
		"cert-ec-bad-signer":        {ctx, certEC, badIdentifier, proto.Priority_Medium, true, true},
		"x509-ec-ca-cert-no-server": {ctx, certEC, defaultIdentifier, proto.Priority_Unspecified_priority, false, false},
	}
	go dummyScheduler(ctx, reqChan)
	for label, tt := range testcases {
		label, tt := label, tt
		t.Run(label, func(t *testing.T) {
			signer := initMockSigner(x509.ECDSA, caPriv, caCert, tt.isBadSigner, timeout, 10)
			var data []byte
			if label == "x509-ec-ca-cert-no-server" {
				data, err = signer.SignX509Cert(tt.ctx, nil, tt.cert, tt.identifier, tt.priority)
			} else {
				data, err = signer.SignX509Cert(tt.ctx, reqChan, tt.cert, tt.identifier, tt.priority)
			}
			if (err != nil) != tt.expectError {
				t.Fatalf("%s: got err: %v, expect err: %v", label, err, tt.expectError)
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
}

func TestSignX509Cert_ContextCancel(t *testing.T) {
	t.Parallel()
	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Foo"},
		OrganizationalUnit: []string{"FooUnit"},
		Locality:           []string{"Bar"},
		Province:           []string{"Baz"},
		CommonName:         "foo.bar.com",
	}
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate EC key: %v", err)
	}
	certEC := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          big.NewInt(0),
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             &eckey.PublicKey,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		DNSNames:              []string{subject.CommonName},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	caPriv, caCert, err := createCAKeysAndCert(x509.ECDSA)
	if err != nil {
		t.Fatalf("unable to create CA keys and certificate: %v", err)
	}
	cp := x509.NewCertPool()
	cp.AddCert(caCert)

	signerTimeoutCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	cancelCtx, cncl := context.WithCancel(context.Background())
	defer cncl()

	reqChan := make(chan scheduler.Request)
	testcases := map[string]struct {
		ctx         context.Context
		cert        *x509.Certificate
		identifier  string
		priority    proto.Priority
		isBadSigner bool
		expectError bool
	}{
		"context-already-expired": {cancelCtx, certEC, defaultIdentifier, proto.Priority_High, false, true},
		"cert-ec-timeout-expired": {signerTimeoutCtx, certEC, defaultIdentifier, proto.Priority_High, false, true},
	}
	go dummyScheduler(context.Background(), reqChan)
	for label, tt := range testcases {
		label, tt := label, tt
		t.Run(label, func(t *testing.T) {
			signer := initMockSigner(x509.ECDSA, caPriv, caCert, tt.isBadSigner, timeout, 10)
			if tt.ctx == cancelCtx {
				cncl()
			}
			data, err := signer.SignX509Cert(tt.ctx, reqChan, tt.cert, tt.identifier, proto.Priority_Unspecified_priority)
			if err != nil != tt.expectError {
				t.Fatalf("%s: got err: %v, expect err: %v", label, err, tt.expectError)
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
}

func TestGetBlobSigningPublicKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	testcases := map[string]struct {
		ctx         context.Context
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"good-signer":         {ctx, defaultIdentifier, false, false},
		"bad-identifier":      {ctx, badIdentifier, false, true},
		"bad-signer":          {ctx, defaultIdentifier, true, true},
		"bad-request-timeout": {timeoutCtx, defaultIdentifier, false, true},
	}
	for label, tt := range testcases {
		label, tt := label, tt
		t.Run(label, func(t *testing.T) {
			caPriv, caCert, err := createCAKeysAndCert(x509.RSA)
			if err != nil {
				t.Fatalf("unable to create CA keys and certificate: %v", err)
			}
			signer := initMockSigner(x509.RSA, caPriv, caCert, tt.isBadSigner, timeout, 10)
			_, err = signer.GetBlobSigningPublicKey(tt.ctx, tt.identifier)
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

	caPriv, caCert, err := createCAKeysAndCert(x509.RSA)
	if err != nil {
		t.Fatalf("unable to create CA keys and certificate: %v", err)
	}
	key, ok := caPriv.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("unable to create RSA CA keys")
	}

	ctx := context.Background()
	timeoutCtx, cancel := context.WithTimeout(ctx, 1*time.Millisecond)
	defer cancel()
	reqChan := make(chan scheduler.Request)
	go dummyScheduler(ctx, reqChan)

	testcases := map[string]struct {
		ctx         context.Context
		digest      []byte
		opts        crypto.SignerOpts
		identifier  string
		isBadSigner bool
		expectError bool
	}{
		"good-SHA224":         {ctx, goodDigestSHA224[:], crypto.SHA224, defaultIdentifier, false, false},
		"good-SHA256":         {ctx, goodDigestSHA256[:], crypto.SHA256, defaultIdentifier, false, false},
		"good-SHA384":         {ctx, goodDigestSHA384[:], crypto.SHA384, defaultIdentifier, false, false},
		"good-SHA512":         {ctx, goodDigestSHA512[:], crypto.SHA512, defaultIdentifier, false, false},
		"bad-digest":          {ctx, []byte("bad digest"), crypto.SHA256, defaultIdentifier, false, true},
		"bad-wrong-hash":      {ctx, goodDigestSHA224[:], crypto.SHA256, defaultIdentifier, false, true},
		"bad-identifier":      {ctx, goodDigestSHA224[:], crypto.SHA256, badIdentifier, false, true},
		"bad-signer":          {ctx, goodDigestSHA224[:], crypto.SHA256, defaultIdentifier, true, true},
		"bad-request-timeout": {timeoutCtx, goodDigestSHA512[:], crypto.SHA512, defaultIdentifier, false, true},
	}
	for label, tt := range testcases {
		label, tt := label, tt
		t.Run(label, func(t *testing.T) {
			signer := initMockSigner(x509.RSA, caPriv, caCert, tt.isBadSigner, timeout, 10)
			signature, err := signer.SignBlob(tt.ctx, reqChan, tt.digest, tt.opts, tt.identifier, proto.Priority_High)
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

func TestIsValidCertRequest(t *testing.T) {
	t.Parallel()
	subject := pkix.Name{
		Country:            []string{"US"},
		Organization:       []string{"Foo"},
		OrganizationalUnit: []string{"FooUnit"},
		Locality:           []string{"Bar"},
		Province:           []string{"Baz"},
		CommonName:         "foo.bar.com",
	}
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("unable to generate EC key: %v", err)
	}
	certEC := &x509.Certificate{
		Subject:               subject,
		SerialNumber:          big.NewInt(0),
		PublicKeyAlgorithm:    x509.ECDSA,
		PublicKey:             &eckey.PublicKey,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24),
		DNSNames:              []string{subject.CommonName},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	tests := map[string]struct {
		sa   x509.SignatureAlgorithm
		want bool
	}{
		"happy path":               {sa: x509.ECDSAWithSHA256, want: true},
		"rsa-public-key-algo":      {sa: x509.SHA256WithRSA, want: false},
		"incorrect-signature-algo": {sa: x509.ECDSAWithSHA384, want: false},
	}
	for name, tt := range tests {
		name, tt := name, tt
		t.Run(name, func(t *testing.T) {
			got := isValidCertRequest(certEC, tt.sa)
			if got != tt.want {
				t.Fatalf("%s: got %v want %v", name, got, tt.want)
			}
		})
	}
}
