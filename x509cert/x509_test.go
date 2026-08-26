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
	"crypto/sha256"
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

// TestGenCACertSubjectKeyID checks that the CA certificate's key identifier is
// derived from the configured hash rather than from whichever algorithm
// x509.CreateCertificate would have filled in for the Go release the binary
// happens to be built with. The identifier is copied into the
// authorityKeyIdentifier of every certificate the CA signs, so it has to stay a
// property of the key and the configuration alone.
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

	keys := map[string]struct {
		signer crypto.Signer
		pka    x509.PublicKeyAlgorithm
		sa     x509.SignatureAlgorithm
	}{
		"ecdsa": {eckey, x509.ECDSA, x509.ECDSAWithSHA384},
		"rsa":   {rsakey, x509.RSA, x509.SHA256WithRSA},
	}
	hashes := map[string]struct {
		configured string
		want       func(*testing.T, crypto.PublicKey) []byte
	}{
		"unset defaults to sha1":     {"", rfc5280KeyID},
		"sha1":                       {crypki.SubjectKeyIdHashSHA1, rfc5280KeyID},
		"sha1 is case-insensitive":   {"sha1", rfc5280KeyID},
		"sha256":                     {crypki.SubjectKeyIdHashSHA256, rfc7093KeyID},
		"sha256 is case-insensitive": {"sha256", rfc7093KeyID},
	}

	for keyName, k := range keys {
		for hashName, h := range hashes {
			keyName, k, hashName, h := keyName, k, hashName, h
			t.Run(keyName+"/"+hashName, func(t *testing.T) {
				t.Parallel()
				cfg := &crypki.CAConfig{CommonName: "foo.example.com", SubjectKeyIdHash: h.configured}
				got, err := GenCACert(cfg, k.signer, "", nil, nil, k.pka, k.sa)
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
				if want := h.want(t, k.signer.Public()); !bytes.Equal(cert.SubjectKeyId, want) {
					t.Errorf("SubjectKeyId = %x, want %x", cert.SubjectKeyId, want)
				}
			})
		}
	}

	t.Run("unknown hash is rejected", func(t *testing.T) {
		t.Parallel()
		cfg := &crypki.CAConfig{CommonName: "foo.example.com", SubjectKeyIdHash: "SHA3-256"}
		if _, err := GenCACert(cfg, eckey, "", nil, nil, x509.ECDSA, x509.ECDSAWithSHA384); err == nil {
			t.Error("GenCACert() expected an error for an unknown SubjectKeyIdHash")
		}
	})

	t.Run("the two methods disagree", func(t *testing.T) {
		t.Parallel()
		if bytes.Equal(rfc5280KeyID(t, eckey.Public()), rfc7093KeyID(t, eckey.Public())) {
			t.Error("RFC 5280 and RFC 7093 key identifiers should differ for the same key")
		}
	})
}

// subjectPublicKeyBytes returns the value of the BIT STRING subjectPublicKey,
// excluding the tag, length and number of unused bits.
func subjectPublicKeyBytes(t *testing.T, pub crypto.PublicKey) []byte {
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
	return spki.SubjectPublicKey.Bytes
}

// rfc5280KeyID and rfc7093KeyID recompute the expected identifiers
// independently of the code under test, so the assertions do not go through the
// same helper they verify.
func rfc5280KeyID(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	sum := sha1.Sum(subjectPublicKeyBytes(t, pub))
	return sum[:]
}

func rfc7093KeyID(t *testing.T, pub crypto.PublicKey) []byte {
	t.Helper()
	sum := sha256.Sum256(subjectPublicKeyBytes(t, pub))
	return sum[:20]
}
