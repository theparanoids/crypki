// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package x509cert

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"reflect"
	"testing"

	"github.com/theparanoids/crypki/proto"
)

func TestDecodeRequest(t *testing.T) {
	t.Parallel()
	goodEKU := []int32{int32(x509.ExtKeyUsageClientAuth), int32(x509.ExtKeyUsageServerAuth)}
	badEKU := []int32{int32(x509.ExtKeyUsageClientAuth), int32(x509.ExtKeyUsageServerAuth), int32(1000)}
	testcases := map[string]struct {
		csrFile     string
		expiryTime  uint64
		eku         []int32
		expectError bool
	}{
		"good-req": {
			csrFile:     "testdata/csr.pem",
			expiryTime:  3600,
			eku:         goodEKU,
			expectError: false,
		},
		"good-req-empty-eku": {
			csrFile:     "testdata/csr.pem",
			expiryTime:  3600,
			eku:         nil,
			expectError: false,
		},
		"bad-req-bad-csr": {
			csrFile:     "testdata/csr-bad.pem",
			expiryTime:  3600,
			eku:         goodEKU,
			expectError: true,
		},
		"bad-req-empty-csr": {
			csrFile:     "testdata/csr-empty.pem",
			expiryTime:  3600,
			eku:         goodEKU,
			expectError: true,
		},
		"bad-req-bad-keyusage": {
			csrFile:     "testdata/csr.pem",
			expiryTime:  3600,
			eku:         badEKU,
			expectError: true,
		},
	}
	for k, tt := range testcases {
		tt := tt // capture range variable - see https://blog.golang.org/subtests
		t.Run(k, func(t *testing.T) {
			t.Parallel()
			pemData, err := os.ReadFile(tt.csrFile)
			if err != nil {
				t.Fatal(err)
			}

			cReq := &proto.X509CertificateSigningRequest{
				Csr:         string(pemData),
				Validity:    tt.expiryTime,
				ExtKeyUsage: tt.eku,
			}

			got, err := DecodeRequest(cReq)
			if err != nil {
				if !tt.expectError {
					t.Errorf("unexpected err: %v", err)
				}
				return
			}
			if tt.expectError {
				t.Error("expected error, got none")
				return
			}

			block, _ := pem.Decode(pemData)
			if block == nil {
				t.Error("empty epm")
				return
			}
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			err = csr.CheckSignature()
			if err != nil {
				t.Fatal(err)
			}

			var x509ExtKeyUsages []x509.ExtKeyUsage
			for _, eku := range tt.eku {
				x509ExtKeyUsages = append(x509ExtKeyUsages, x509.ExtKeyUsage(eku))
			}
			if len(x509ExtKeyUsages) == 0 {
				x509ExtKeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			}
			want := &x509.Certificate{
				Subject:               csr.Subject,
				PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
				PublicKey:             csr.PublicKey,
				SignatureAlgorithm:    x509.SHA256WithRSA,
				DNSNames:              csr.DNSNames,
				IPAddresses:           csr.IPAddresses,
				EmailAddresses:        csr.EmailAddresses,
				URIs:                  csr.URIs,
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtKeyUsage:           x509ExtKeyUsages,
				BasicConstraintsValid: true,
			}

			// cannot validate ValidBefore, ValidAfter and SerialNumber fields because
			// those value created by server
			want.NotAfter = got.NotAfter
			want.NotBefore = got.NotBefore
			want.SerialNumber = got.SerialNumber

			if got.NotAfter.Sub(got.NotBefore).Seconds() != float64(tt.expiryTime+3600) {
				t.Errorf("validity mismatch: got: %v, want: %v", got.NotAfter.Sub(got.NotBefore).Seconds(), tt.expiryTime+3600)
				return
			}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("Cert got: \n%+v\n want: \n%+v\n", got, want)
				return
			}

		})
	}
}
