// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package api

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/proto"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	timeout = 1 * time.Second
)

func TestGetX509CertificateAvailableSigningKeys(t *testing.T) {
	t.Parallel()
	var expectedEmptyKey []*proto.KeyMeta
	expectedEmptyKeyMeta := &proto.KeyMetas{Keys: expectedEmptyKey}
	var expectedOneKey []*proto.KeyMeta
	expectedOneKey = append(expectedOneKey, &proto.KeyMeta{Identifier: "x509id"})
	expectedOneKeyMeta := &proto.KeyMetas{Keys: expectedOneKey}
	var expectedTwoKeys []*proto.KeyMeta
	expectedTwoKeys = append(expectedTwoKeys, &proto.KeyMeta{Identifier: "x509id1"})
	expectedTwoKeys = append(expectedTwoKeys, &proto.KeyMeta{Identifier: "x509id2"})
	expectedTwoKeyMeta := &proto.KeyMetas{Keys: expectedTwoKeys}
	testcases := map[string]struct {
		KeyUsages      map[string]map[string]bool
		expectKeyMetas *proto.KeyMetas
	}{
		"emptyKeyUsages": {
			expectKeyMetas: expectedEmptyKeyMeta,
		},
		"x509KeyUsages": {
			KeyUsages:      x509keyUsage,
			expectKeyMetas: expectedOneKeyMeta,
		},
		"sshKeyUsages": {
			KeyUsages:      sshkeyUsage,
			expectKeyMetas: expectedEmptyKeyMeta,
		},
		"combineKeyUsages": {
			KeyUsages:      combineKeyUsage,
			expectKeyMetas: expectedTwoKeyMeta,
		},
	}
	for label, tt := range testcases {
		tt := tt
		label := label
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			mssp := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: false}
			ss := initMockSigningService(mssp)
			var ctx context.Context
			var e *emptypb.Empty
			keyMetas, err := ss.GetX509CertificateAvailableSigningKeys(ctx, e)
			if err != nil {
				t.Fatal(err)
				return
			}
			// we get keyMetas from a map,  which are unsorted
			// we need to sort keyMetas before comparing it with expectKeyMetas
			sort.Slice(keyMetas.Keys, func(i, j int) bool {
				return keyMetas.Keys[i].Identifier < keyMetas.Keys[j].Identifier
			})
			if !reflect.DeepEqual(keyMetas, tt.expectKeyMetas) {
				t.Errorf("in test %v: key metas mismatch: got \n%+v\n, want: \n%+v\n", label, keyMetas, tt.expectKeyMetas)
				return
			}
		})
	}
}

func TestGetX509CACertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timeoutCtx, timeCancel := context.WithTimeout(ctx, timeout)
	defer timeCancel()
	testcases := map[string]struct {
		ctx       context.Context
		KeyUsages map[string]map[string]bool
		KeyMeta   *proto.KeyMeta
		// if expectedCert set to nil, we are expecting an error while testing
		expectedCert *proto.X509Certificate
		timeout      time.Duration
	}{
		"emptyKeyUsages": {
			KeyMeta:      &proto.KeyMeta{Identifier: "randomid"},
			expectedCert: nil,
		},
		"emptyKeyMeta": {
			expectedCert: nil,
		},
		"x509KeyUsagesWithWrongId": {
			KeyUsages:    x509keyUsage,
			KeyMeta:      &proto.KeyMeta{Identifier: "randomId"},
			expectedCert: nil,
		},
		"x509KeyUsagesWithRightId": {
			KeyUsages:    x509keyUsage,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id"},
			expectedCert: &proto.X509Certificate{Cert: "good x509 ca cert"},
		},
		"sshKeyUsages": {
			KeyUsages:    sshkeyUsage,
			KeyMeta:      &proto.KeyMeta{Identifier: "sshuserid"},
			expectedCert: nil,
		},
		"combineKeyUsagesWithTrueIdSet": {
			KeyUsages:    combineKeyUsage,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id1"},
			expectedCert: &proto.X509Certificate{Cert: "good x509 ca cert"},
		},
		"combineKeyUsagesWithFalseIdSet": {
			KeyUsages:    combineKeyUsage,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id2"},
			expectedCert: nil,
		},
		"requestTimeout": {
			ctx:          timeoutCtx,
			KeyUsages:    x509keyUsage,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id"},
			expectedCert: nil,
			timeout:      timeout,
		},
		"requestCancelled": {
			ctx:          cancelCtx,
			KeyUsages:    x509keyUsage,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id"},
			expectedCert: nil,
			timeout:      timeout,
		},
	}
	for label, tt := range testcases {
		tt := tt
		label := label
		if tt.ctx == nil {
			tt.ctx = ctx
		}
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			// bad certsign should return error anyways
			msspBad := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: true, timeout: tt.timeout}
			ssBad := initMockSigningService(msspBad)
			_, err := ssBad.GetX509CACertificate(tt.ctx, tt.KeyMeta)
			if err == nil {
				t.Fatalf("in test %v: bad signing service should return error but got nil", label)
			}
			// good certsign
			msspGood := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: false, timeout: tt.timeout}
			ssGood := initMockSigningService(msspGood)
			cert, err := ssGood.GetX509CACertificate(tt.ctx, tt.KeyMeta)
			if err != nil && tt.expectedCert != nil {
				t.Fatalf("in test %v: not expecting error but got error %v", label, err)
			}
			if err == nil && tt.expectedCert == nil {
				t.Fatalf("in test %v: expecting error but got no error", label)
			}
			if tt.expectedCert != nil {
				if !reflect.DeepEqual(cert, tt.expectedCert) {
					t.Errorf("in test %v: cert mismatch: got \n%+v\n, want: \n%+v\n", label, cert, tt.expectedCert)
					return
				}
			}
		})
	}
}

func TestPostX509Certificate(t *testing.T) {
	t.Parallel()
	defaultMaxValidity := map[string]uint64{config.X509CertEndpoint: 0}
	ctx := context.Background()
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timeoutCtx, timeCancel := context.WithTimeout(ctx, timeout)
	defer timeCancel()

	testcases := map[string]struct {
		ctx         context.Context
		KeyUsages   map[string]map[string]bool
		maxValidity map[string]uint64
		validity    uint64
		KeyMeta     *proto.KeyMeta
		// if expectedCert set to nil, we are expecting an error while testing
		expectedCert *proto.X509Certificate
		CSR          string
		timeout      time.Duration
	}{
		"emptyKeyUsages": {
			KeyMeta:      &proto.KeyMeta{Identifier: "randomid"},
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			expectedCert: nil,
			CSR:          testGoodcsrRsa,
		},
		"emptyKeyMeta": {
			expectedCert: nil,
			maxValidity:  defaultMaxValidity,
			CSR:          testGoodcsrRsa,
		},
		"x509KeyUsagesWithWrongId": {
			KeyUsages:    x509keyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "randomId"},
			expectedCert: nil,
			CSR:          testGoodcsrRsa,
		},
		"x509KeyUsagesWithRightId": {
			KeyUsages:    x509keyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id"},
			expectedCert: &proto.X509Certificate{Cert: "good x509 cert"},
			CSR:          testGoodcsrRsa,
		},
		"x509KeyUsagesWithRightIdAndEcdsaCsr": {
			KeyUsages:    x509keyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id"},
			expectedCert: &proto.X509Certificate{Cert: "good x509 cert"},
			CSR:          testGoodcsrEc,
		},
		"x509KeyUsagesWithRightIdAndED25519Csr": {
			KeyUsages:    x509keyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id"},
			expectedCert: &proto.X509Certificate{Cert: "good x509 cert"},
			CSR:          testGoodcsrED25519,
		},
		"sshKeyUsages": {
			KeyUsages:    sshkeyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "sshuserid"},
			expectedCert: nil,
			CSR:          testGoodcsrRsa,
		},
		"combineKeyUsagesWithTrueIdAndInvalidCSR": {
			KeyUsages:    combineKeyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id1"},
			expectedCert: nil,
			CSR:          "badcsr",
		},
		"combineKeyUsagesWithTrueId": {
			KeyUsages:    combineKeyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id1"},
			expectedCert: &proto.X509Certificate{Cert: "good x509 cert"},
			CSR:          testGoodcsrRsa,
		},
		"combineKeyUsagesWithFalseIdSet": {
			KeyUsages:    combineKeyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id2"},
			expectedCert: nil,
			CSR:          testGoodcsrRsa,
		},
		"valid validity": {
			KeyUsages:    combineKeyUsage,
			maxValidity:  map[string]uint64{config.X509CertEndpoint: 3600},
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id1"},
			expectedCert: &proto.X509Certificate{Cert: "good x509 cert"},
			CSR:          testGoodcsrRsa,
		},
		"missing validity": {
			KeyUsages:    combineKeyUsage,
			maxValidity:  map[string]uint64{config.X509CertEndpoint: 3600},
			validity:     0,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id1"},
			expectedCert: nil,
			CSR:          testGoodcsrRsa,
		},
		"validity greater than maxValidity": {
			KeyUsages:    combineKeyUsage,
			maxValidity:  map[string]uint64{config.X509CertEndpoint: 3600},
			validity:     3601,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id1"},
			expectedCert: nil,
			CSR:          testGoodcsrRsa,
		},
		"requestTimeout": {
			ctx:          timeoutCtx,
			KeyUsages:    combineKeyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id1"},
			expectedCert: nil,
			CSR:          testGoodcsrRsa,
			timeout:      2 * timeout,
		},
		"requestCancelled": {
			ctx:          cancelCtx,
			KeyUsages:    combineKeyUsage,
			maxValidity:  defaultMaxValidity,
			validity:     3600,
			KeyMeta:      &proto.KeyMeta{Identifier: "x509id1"},
			expectedCert: nil,
			CSR:          testGoodcsrRsa,
			timeout:      2 * timeout,
		},
	}
	for label, tt := range testcases {
		tt := tt
		label := label
		if tt.ctx == nil {
			tt.ctx = ctx
		}
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			// bad certsign should return error anyways
			msspBad := mockSigningServiceParam{KeyUsages: tt.KeyUsages, MaxValidity: tt.maxValidity, sendError: true, timeout: tt.timeout}
			ssBad := initMockSigningService(msspBad)
			requestBad := &proto.X509CertificateSigningRequest{KeyMeta: tt.KeyMeta, Csr: tt.CSR, Validity: tt.validity}
			if _, err := ssBad.PostX509Certificate(tt.ctx, requestBad); err == nil {
				t.Fatalf("expected error for invalid test %v, got nil", label)
			}

			// good certsign
			msspGood := mockSigningServiceParam{KeyUsages: tt.KeyUsages, MaxValidity: tt.maxValidity, sendError: false, timeout: tt.timeout}
			ssGood := initMockSigningService(msspGood)
			requestGood := &proto.X509CertificateSigningRequest{KeyMeta: tt.KeyMeta, Csr: tt.CSR, Validity: tt.validity}
			cert, err := ssGood.PostX509Certificate(tt.ctx, requestGood)
			if tt.expectedCert == nil {
				if err == nil {
					t.Errorf("expected error for invalid test %v, got nil", label)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %v, err: %v", label, err)
				}
				if !reflect.DeepEqual(cert, tt.expectedCert) {
					t.Errorf("output doesn't match for %v, got %+v\nwant %+v", label, cert, tt.expectedCert)
				}
			}
			if label == "requestCancelled" {
				// this is to test the behavior when client cancels the request while
				// server is still processing the request.
				cancel()
			}
		})
	}
}
