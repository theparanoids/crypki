// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package x509cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"reflect"
	"testing"

	"github.com/theparanoids/crypki/proto"
)

func TestDecodeRequest(t *testing.T) {
	t.Parallel()
	goodEKU := []int32{int32(x509.ExtKeyUsageServerAuth), int32(x509.ExtKeyUsageClientAuth)}
	goodEKUCrit := []int32{int32(x509.ExtKeyUsageTimeStamping)}
	goodEKUCritNonCrit := []int32{int32(x509.ExtKeyUsageServerAuth), int32(x509.ExtKeyUsageTimeStamping), int32(x509.ExtKeyUsageClientAuth)}
	goodEKUAll := []int32{
		int32(x509.ExtKeyUsageAny),
		int32(x509.ExtKeyUsageServerAuth),
		int32(x509.ExtKeyUsageClientAuth),
		int32(x509.ExtKeyUsageCodeSigning),
		int32(x509.ExtKeyUsageEmailProtection),
		int32(x509.ExtKeyUsageIPSECEndSystem),
		int32(x509.ExtKeyUsageIPSECTunnel),
		int32(x509.ExtKeyUsageIPSECUser),
		int32(x509.ExtKeyUsageTimeStamping),
		int32(x509.ExtKeyUsageOCSPSigning),
		int32(x509.ExtKeyUsageMicrosoftServerGatedCrypto),
		int32(x509.ExtKeyUsageNetscapeServerGatedCrypto),
		int32(x509.ExtKeyUsageMicrosoftCommercialCodeSigning),
		int32(x509.ExtKeyUsageMicrosoftKernelCodeSigning),
	}
	badEKU := []int32{int32(x509.ExtKeyUsageClientAuth), int32(x509.ExtKeyUsageServerAuth), int32(1000)}
	eku, err := asn1.Marshal([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 1}, // server auth
		{1, 3, 6, 1, 5, 5, 7, 3, 2}, // client auth
	},
	)
	if err != nil {
		t.Fatal(err)
	}
	ekuCrit, err := asn1.Marshal([]asn1.ObjectIdentifier{
		{1, 3, 6, 1, 5, 5, 7, 3, 8}, // timestamping
	},
	)

	if err != nil {
		t.Fatal(err)
	}
	ekuAllASN, err := asn1.Marshal([]asn1.ObjectIdentifier{
		{2, 5, 29, 37, 0},
		{1, 3, 6, 1, 5, 5, 7, 3, 1},
		{1, 3, 6, 1, 5, 5, 7, 3, 2},
		{1, 3, 6, 1, 5, 5, 7, 3, 3},
		{1, 3, 6, 1, 5, 5, 7, 3, 4},
		{1, 3, 6, 1, 5, 5, 7, 3, 5},
		{1, 3, 6, 1, 5, 5, 7, 3, 6},
		{1, 3, 6, 1, 5, 5, 7, 3, 7},
		{1, 3, 6, 1, 5, 5, 7, 3, 9},
		{1, 3, 6, 1, 4, 1, 311, 10, 3, 3},
		{2, 16, 840, 1, 113730, 4, 1},
		{1, 3, 6, 1, 4, 1, 311, 2, 1, 22},
		{1, 3, 6, 1, 4, 1, 311, 61, 1, 1},
	},
	)
	if err != nil {
		t.Fatal(err)
	}

	ext := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: false,
		Value:    eku,
	}
	extCrit := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: true,
		Value:    ekuCrit,
	}
	extAll := pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: false,
		Value:    ekuAllASN,
	}
	defaultEKU := []pkix.Extension{ext}
	critEKU := []pkix.Extension{extCrit}
	critNonCritEKU := []pkix.Extension{extCrit, ext}
	ekuAll := []pkix.Extension{extCrit, extAll}
	testcases := map[string]struct {
		csrFile     string
		expiryTime  uint64
		eku         []int32
		ext         []pkix.Extension
		expectError bool
	}{
		"good-req": {
			csrFile:     "testdata/csr.pem",
			expiryTime:  3600,
			eku:         goodEKU,
			ext:         defaultEKU,
			expectError: false,
		},
		"good-req-crit": {
			csrFile:     "testdata/csr.pem",
			expiryTime:  3600,
			eku:         goodEKUCrit,
			ext:         critEKU,
			expectError: false,
		},
		"good-req-crit-noncrit": {
			csrFile:     "testdata/csr.pem",
			expiryTime:  3600,
			eku:         goodEKUCritNonCrit,
			ext:         critNonCritEKU,
			expectError: false,
		},
		"good-req-eku-all": {
			csrFile:     "testdata/csr.pem",
			expiryTime:  3600,
			eku:         goodEKUAll,
			ext:         ekuAll,
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

			var x509ExtKeyUsages []pkix.Extension
			x509ExtKeyUsages = tt.ext
			if len(x509ExtKeyUsages) == 0 {
				x509ExtKeyUsages = defaultEKU
			}
			want := &x509.Certificate{
				Subject:               csr.Subject,
				PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
				PublicKey:             csr.PublicKey,
				SignatureAlgorithm:    csr.SignatureAlgorithm,
				DNSNames:              csr.DNSNames,
				IPAddresses:           csr.IPAddresses,
				EmailAddresses:        csr.EmailAddresses,
				URIs:                  csr.URIs,
				KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
				ExtraExtensions:       x509ExtKeyUsages,
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
