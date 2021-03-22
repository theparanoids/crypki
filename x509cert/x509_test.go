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
		pka  crypki.PublicKeyAlgorithm
		sa   crypki.SignatureAlgorithm
		want x509.SignatureAlgorithm
	}{
		"rsa key & signature": {
			pka:  crypki.RSA,
			sa:   crypki.SHA256WithRSA,
			want: x509.SHA256WithRSA,
		},
		"ec key & 384 signature": {
			pka:  crypki.ECDSA,
			sa:   crypki.ECDSAWithSHA384,
			want: x509.ECDSAWithSHA384,
		},
		"ec key & 256 signature": {
			pka:  crypki.ECDSA,
			sa:   crypki.ECDSAWithSHA256,
			want: x509.ECDSAWithSHA256,
		},
		"no signature algo rsa key": {
			pka:  crypki.RSA,
			sa:   crypki.UnknownSignatureAlgorithm,
			want: x509.SHA256WithRSA,
		},
		"no signature algo ec key": {
			pka:  crypki.ECDSA,
			sa:   crypki.UnknownSignatureAlgorithm,
			want: x509.ECDSAWithSHA384,
		},
	}
	for name, tt := range tests {
		name, tt := name, tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got := GetSignatureAlgorithm(tt.pka, tt.sa)
			if got != tt.want {
				t.Errorf("%s: got %d want %d", name, got, tt.want)
			}
		})
	}
}
