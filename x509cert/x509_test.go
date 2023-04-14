// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package x509cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
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
