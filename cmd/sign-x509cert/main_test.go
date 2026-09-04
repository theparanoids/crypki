// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestNewSerial(t *testing.T) {
	t.Parallel()

	// The serial is drawn below 2^94 and then shifted left by 64 bits, so it
	// stays inside the 160 bits RFC 5280 allows while keeping at least the 64
	// bits of entropy the CA/Browser Forum requires.
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		serial := newSerial()
		if serial.Sign() < 0 {
			t.Fatalf("newSerial() = %v, want a non-negative serial", serial)
		}
		if serial.BitLen() > 158 {
			t.Errorf("newSerial() has %d bits, want at most 158", serial.BitLen())
		}
		low := new(big.Int).And(serial, new(big.Int).SetUint64(^uint64(0)))
		if low.Sign() != 0 {
			t.Errorf("newSerial() low 64 bits = %v, want 0", low)
		}
		seen[serial.String()] = true
	}
	if len(seen) < 2 {
		t.Error("newSerial() returned the same serial every time")
	}
}

// writeCSR writes a certificate request carrying every SAN type
// constructUnsignedX509Cert copies, and returns its path.
func writeCSR(t *testing.T, template *x509.CertificateRequest) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatalf("failed to create CSR: %v", err)
	}
	path := filepath.Join(t.TempDir(), "request.csr")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0600); err != nil {
		t.Fatalf("failed to write CSR: %v", err)
	}
	return path
}

// TestConstructUnsignedX509Cert reads the package level csrPath and
// validityDays that parseFlags would have set, so it cannot run in parallel
// with anything else that touches them.
func TestConstructUnsignedX509Cert(t *testing.T) {
	uri, err := url.Parse("spiffe://example.com/svc")
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: "foo.example.com", Organization: []string{"Yahoo Inc."}},
		DNSNames:           []string{"foo.example.com", "bar.example.com"},
		IPAddresses:        []net.IP{net.ParseIP("127.0.0.1")},
		EmailAddresses:     []string{"foo@example.com"},
		URIs:               []*url.URL{uri},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	oldCSRPath, oldValidityDays := csrPath, validityDays
	t.Cleanup(func() { csrPath, validityDays = oldCSRPath, oldValidityDays })
	csrPath = writeCSR(t, template)
	validityDays = 30

	before := time.Now()
	cert := constructUnsignedX509Cert()

	if cert.Subject.CommonName != template.Subject.CommonName {
		t.Errorf("Subject.CommonName = %q, want %q", cert.Subject.CommonName, template.Subject.CommonName)
	}
	if !reflect.DeepEqual(cert.DNSNames, template.DNSNames) {
		t.Errorf("DNSNames = %v, want %v", cert.DNSNames, template.DNSNames)
	}
	if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(template.IPAddresses[0]) {
		t.Errorf("IPAddresses = %v, want %v", cert.IPAddresses, template.IPAddresses)
	}
	if !reflect.DeepEqual(cert.EmailAddresses, template.EmailAddresses) {
		t.Errorf("EmailAddresses = %v, want %v", cert.EmailAddresses, template.EmailAddresses)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != uri.String() {
		t.Errorf("URIs = %v, want %v", cert.URIs, template.URIs)
	}
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		t.Errorf("PublicKeyAlgorithm = %v, want %v", cert.PublicKeyAlgorithm, x509.ECDSA)
	}
	if cert.SignatureAlgorithm != template.SignatureAlgorithm {
		t.Errorf("SignatureAlgorithm = %v, want %v", cert.SignatureAlgorithm, template.SignatureAlgorithm)
	}
	if cert.PublicKey == nil {
		t.Error("PublicKey was not copied from the CSR")
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() < 0 {
		t.Errorf("SerialNumber = %v, want a non-negative serial", cert.SerialNumber)
	}
	if !cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid = false, want true")
	}
	if cert.KeyUsage != x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature {
		t.Errorf("KeyUsage = %v, want KeyEncipherment|DigitalSignature", cert.KeyUsage)
	}
	wantExtKeyUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	if !reflect.DeepEqual(cert.ExtKeyUsage, wantExtKeyUsage) {
		t.Errorf("ExtKeyUsage = %v, want %v", cert.ExtKeyUsage, wantExtKeyUsage)
	}

	// NotBefore is backdated an hour to absorb clock drift, and the validity
	// window runs validityDays from the moment the cert is constructed.
	if !cert.NotBefore.Before(before) {
		t.Errorf("NotBefore = %v, want a backdated time before %v", cert.NotBefore, before)
	}
	gotValidity := cert.NotAfter.Sub(cert.NotBefore).Round(time.Hour)
	wantValidity := time.Duration(validityDays)*24*time.Hour + time.Hour
	if gotValidity != wantValidity {
		t.Errorf("validity window = %v, want %v", gotValidity, wantValidity)
	}
}
