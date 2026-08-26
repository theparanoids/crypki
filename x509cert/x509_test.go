// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package x509cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"net/url"
	"reflect"
	"testing"

	"github.com/theparanoids/crypki"
)

func TestGenCACert(t *testing.T) {
	t.Parallel()
	pka := x509.ECDSA
	sa := x509.ECDSAWithSHA384
	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spiffeUri, _ := url.Parse("spiffe://paranoids/crypki")
	uris := []*url.URL{spiffeUri}

	tests := map[string]struct {
		cfg         *crypki.CAConfig
		signer      crypto.Signer
		hostname    string
		ips         []net.IP
		uris        []*url.URL
		pka         x509.PublicKeyAlgorithm
		sa          x509.SignatureAlgorithm
		wantSubj    pkix.Name
		expectError bool
	}{
		"all-fields": {
			cfg: &crypki.CAConfig{
				Country:            "US",
				Locality:           "Sunnyvale",
				State:              "CA",
				Organization:       "Foo Org",
				OrganizationalUnit: "Foo Org Unit",
				CommonName:         "foo.example.com",
			},
			signer:   eckey,
			hostname: "hostname.example.com",
			pka:      pka,
			sa:       sa,
			wantSubj: pkix.Name{
				CommonName:         "foo.example.com",
				Country:            []string{"US"},
				Locality:           []string{"Sunnyvale"},
				Province:           []string{"CA"},
				Organization:       []string{"Foo Org"},
				OrganizationalUnit: []string{"Foo Org Unit"},
			},
		},
		"no-hostname-with-uri": {
			cfg: &crypki.CAConfig{
				Country:            "US",
				Locality:           "Sunnyvale",
				State:              "CA",
				Organization:       "Foo Org",
				OrganizationalUnit: "Foo Org Unit",
				CommonName:         "foo.example.com",
			},
			signer: eckey,
			uris:   uris,
			pka:    pka,
			sa:     sa,
			wantSubj: pkix.Name{
				CommonName:         "foo.example.com",
				Country:            []string{"US"},
				Locality:           []string{"Sunnyvale"},
				Province:           []string{"CA"},
				Organization:       []string{"Foo Org"},
				OrganizationalUnit: []string{"Foo Org Unit"},
			},
		},
		"no-ST": {
			cfg: &crypki.CAConfig{
				Country:            "US",
				Locality:           "Sunnyvale",
				Organization:       "Foo Org",
				OrganizationalUnit: "Foo Org Unit",
				CommonName:         "foo.example.com",
			},
			signer:   eckey,
			hostname: "hostname.example.com",
			pka:      pka,
			sa:       sa,
			wantSubj: pkix.Name{
				CommonName:         "foo.example.com",
				Country:            []string{"US"},
				Locality:           []string{"Sunnyvale"},
				Organization:       []string{"Foo Org"},
				OrganizationalUnit: []string{"Foo Org Unit"},
			},
		},
		"no-L": {
			cfg: &crypki.CAConfig{
				Country:            "US",
				State:              "CA",
				Organization:       "Foo Org",
				OrganizationalUnit: "Foo Org Unit",
				CommonName:         "foo.example.com",
			},
			signer:   eckey,
			hostname: "hostname.example.com",
			pka:      pka,
			sa:       sa,
			wantSubj: pkix.Name{
				CommonName:         "foo.example.com",
				Country:            []string{"US"},
				Province:           []string{"CA"},
				Organization:       []string{"Foo Org"},
				OrganizationalUnit: []string{"Foo Org Unit"},
			},
		},
		"no-Org": {
			cfg: &crypki.CAConfig{
				Country:            "US",
				Locality:           "Sunnyvale",
				State:              "CA",
				OrganizationalUnit: "Foo Org Unit",
				CommonName:         "foo.example.com",
			},
			signer:   eckey,
			hostname: "hostname.example.com",
			pka:      pka,
			sa:       sa,
			wantSubj: pkix.Name{
				CommonName:         "foo.example.com",
				Country:            []string{"US"},
				Locality:           []string{"Sunnyvale"},
				Province:           []string{"CA"},
				OrganizationalUnit: []string{"Foo Org Unit"},
			},
		},
		// TODO: add tests to validate other fields in the ca cert, including the signature.
	}
	for name, tt := range tests {
		name, tt := name, tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := GenCACert(tt.cfg, tt.signer, tt.hostname, tt.ips, tt.uris, tt.pka, tt.sa)
			if err != nil {
				if !tt.expectError {
					t.Error("unexpected error")
				}
			}
			if tt.expectError {
				t.Error("expected error")
			}
			block, _ := pem.Decode(got)
			if block == nil || block.Type != "CERTIFICATE" {
				t.Error("unable to decode PEM block containing the certificate")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Error("failed to parse certificate: " + err.Error())
			}
			// skip checking Names field in subject
			tt.wantSubj.Names = cert.Subject.Names
			if !reflect.DeepEqual(cert.Subject, tt.wantSubj) {
				t.Errorf("subject mismatch:\n got: \n%+v\n want: \n%+v\n", cert.Subject, tt.wantSubj)
			}
			if len(tt.uris) > 0 {
				if !reflect.DeepEqual(cert.URIs, tt.uris) {
					t.Errorf("uri mismatch: %+v\n", cert.URIs)
				}
			}
			if tt.hostname != "" {
				if tt.hostname != cert.DNSNames[0] {
					t.Errorf("dnsName mismatch: got:%s want: %s\n", cert.DNSNames[0], tt.hostname)
				}
			} else {
				if len(cert.DNSNames) > 0 {
					t.Errorf("unexpected dnsName values: %s\n", cert.DNSNames[0])
				}
			}
		})
	}

}

// TestGenCACertSubjectKeyID checks that the CA certificate carries a key
// identifier derived with method 1 of RFC 5280, Section 4.2.1.2, rather than
// whichever algorithm x509.CreateCertificate would have filled in for the Go
// release the binary happens to be built with. The identifier is copied into
// the authorityKeyIdentifier of every certificate the CA signs, so it has to
// stay a property of the key alone.
func TestGenCACertSubjectKeyID(t *testing.T) {
	t.Parallel()

	eckey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsakey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string]struct {
		signer crypto.Signer
		pka    x509.PublicKeyAlgorithm
		sa     x509.SignatureAlgorithm
	}{
		"ecdsa": {eckey, x509.ECDSA, x509.ECDSAWithSHA384},
		"rsa":   {rsakey, x509.RSA, x509.SHA256WithRSA},
	}

	for name, tt := range tests {
		name, tt := name, tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := GenCACert(&crypki.CAConfig{CommonName: "foo.example.com"}, tt.signer, "", nil, nil, tt.pka, tt.sa)
			if err != nil {
				t.Fatalf("GenCACert() error = %v", err)
			}
			block, _ := pem.Decode(got)
			if block == nil {
				t.Fatal("unable to decode PEM block containing the certificate")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}
			if want := rfc5280KeyID(t, tt.signer.Public()); !bytes.Equal(cert.SubjectKeyId, want) {
				t.Errorf("SubjectKeyId = %x, want %x (RFC 5280 method 1)", cert.SubjectKeyId, want)
			}
		})
	}
}

// rfc5280KeyID recomputes the expected key identifier independently of the code
// under test, so the assertion does not go through the same helper it verifies.
func rfc5280KeyID(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("unable to marshal public key: %v", err)
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		t.Fatalf("unable to parse public key: %v", err)
	}
	sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return sum[:]
}
