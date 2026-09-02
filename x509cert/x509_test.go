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
	"encoding/hex"
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

// TestSubjectKeyID covers what this package adds on top of
// crypki.ParseSubjectKeyId, which owns the grammar and is tested there: that a
// hash spec is derived from the right key with the right digest, that a literal
// reaches the certificate untouched, and that a parse error is propagated.
func TestSubjectKeyID(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public()

	tests := map[string]struct {
		spec string
		want []byte
	}{
		"unset derives with sha1":              {"", rfc5280KeyID(t, pub)},
		"sha1 derives with sha1":               {crypki.SubjectKeyIdSHA1, rfc5280KeyID(t, pub)},
		"sha256 derives with sha256 truncated": {crypki.SubjectKeyIdSHA256, rfc7093KeyID(t, pub)},
		"hex literal is untouched":             {"hex:0a0b0c", []byte{0x0a, 0x0b, 0x0c}},
		"text literal is untouched":            {"text:  Mixed:Case  ", []byte("  Mixed:Case  ")},
	}
	for name, tt := range tests {
		name, tt := name, tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := subjectKeyID(pub, tt.spec)
			if err != nil {
				t.Fatalf("subjectKeyID(%q) error = %v", tt.spec, err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Errorf("subjectKeyID(%q) = %x, want %x", tt.spec, got, tt.want)
			}
		})
	}

	t.Run("the two hashes disagree", func(t *testing.T) {
		t.Parallel()
		if bytes.Equal(rfc5280KeyID(t, pub), rfc7093KeyID(t, pub)) {
			t.Error("RFC 5280 and RFC 7093 key identifiers should differ for the same key")
		}
	})

	t.Run("a parse error is propagated", func(t *testing.T) {
		t.Parallel()
		if _, err := subjectKeyID(pub, "hash:md5"); err == nil {
			t.Error("subjectKeyID() expected an error for an unknown hash")
		}
	})
}

// TestGenCACertSubjectKeyID checks that the identifier resolved from the config
// actually reaches the certificate, rather than being replaced by whichever
// algorithm x509.CreateCertificate would have filled in for the Go release the
// binary happens to be built with. The identifier is copied into the
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
	specs := map[string]struct {
		spec string
		want func(*testing.T, crypto.PublicKey) []byte
	}{
		"unset":  {"", rfc5280KeyID},
		"sha1":   {crypki.SubjectKeyIdSHA1, rfc5280KeyID},
		"sha256": {crypki.SubjectKeyIdSHA256, rfc7093KeyID},
		"hex literal": {"hex:6802eca0a62b9c8053b807f3caefe683bc2f136e", func(t *testing.T, _ crypto.PublicKey) []byte {
			return mustHex(t, "6802eca0a62b9c8053b807f3caefe683bc2f136e")
		}},
		"text literal": {"text:athenz-ca", func(t *testing.T, _ crypto.PublicKey) []byte {
			return []byte("athenz-ca")
		}},
	}

	for keyName, k := range keys {
		for specName, sp := range specs {
			keyName, k, specName, sp := keyName, k, specName, sp
			t.Run(keyName+"/"+specName, func(t *testing.T) {
				t.Parallel()
				cfg := &crypki.CAConfig{CommonName: "foo.example.com", SubjectKeyId: sp.spec}
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
				if want := sp.want(t, k.signer.Public()); !bytes.Equal(cert.SubjectKeyId, want) {
					t.Errorf("SubjectKeyId = %x, want %x", cert.SubjectKeyId, want)
				}
			})
		}
	}

	t.Run("a rejected spec fails the whole call", func(t *testing.T) {
		t.Parallel()
		cfg := &crypki.CAConfig{CommonName: "foo.example.com", SubjectKeyId: "hash:md5"}
		if _, err := GenCACert(cfg, eckey, "", nil, nil, x509.ECDSA, x509.ECDSAWithSHA384); err == nil {
			t.Error("GenCACert() expected an error for an unknown SubjectKeyId hash")
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
	return sum[:sha1.Size]
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test fixture %q: %v", s, err)
	}
	return b
}
