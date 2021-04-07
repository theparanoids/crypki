// Copyright 2020, Verizon Media Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package x509cert

import (
	"crypto/x509"
	"testing"

	"github.com/theparanoids/crypki"
)

func TestGetSignatureAlgorithm(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		sa   crypki.SignatureAlgorithm
		want x509.SignatureAlgorithm
	}{
		"rsa key & signature": {
			sa:   crypki.SHA256WithRSA,
			want: x509.SHA256WithRSA,
		},
		"ec key & 384 signature": {
			sa:   crypki.ECDSAWithSHA384,
			want: x509.ECDSAWithSHA384,
		},
		"ec key & 256 signature": {
			sa:   crypki.ECDSAWithSHA256,
			want: x509.ECDSAWithSHA256,
		},
		"no signature algo": {
			sa:   crypki.UnknownSignatureAlgorithm,
			want: x509.SHA256WithRSA,
		},
	}
	for name, tt := range tests {
		name, tt := name, tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := GetSignatureAlgorithm(tt.sa)
			if got != tt.want {
				t.Errorf("%s: got %d want %d", name, got, tt.want)
			}
		})
	}
}

func TestGetPublicKeyAlgorithm(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		pka  crypki.PublicKeyAlgorithm
		want x509.PublicKeyAlgorithm
	}{
		"rsa":         {pka: crypki.RSA, want: x509.RSA},
		"ec key":      {pka: crypki.ECDSA, want: x509.ECDSA},
		"unknown key": {pka: crypki.UnknownPublicKeyAlgorithm, want: x509.RSA},
	}
	for name, tt := range tests {
		name, tt := name, tt
		t.Run(name, func(t *testing.T) {
			got := GetPublicKeyAlgorithm(tt.pka)
			if got != tt.want {
				t.Fatalf("%s: got %d want %d", name, got, tt.want)
			}
		})
	}
}
