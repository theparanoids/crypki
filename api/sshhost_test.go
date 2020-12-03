// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package api

import (
	"context"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/proto"
)

func TestGetHostSSHCertificateAvailableSigningKeys(t *testing.T) {
	t.Parallel()
	var expectedEmptyKey []*proto.KeyMeta
	expectedEmptyKeyMeta := &proto.KeyMetas{Keys: expectedEmptyKey}
	var expectedForSSH []*proto.KeyMeta
	expectedForSSH = append(expectedForSSH, &proto.KeyMeta{Identifier: "sshhostid"})
	expectedForSSHMeta := &proto.KeyMetas{Keys: expectedForSSH}
	var expectedForCombined []*proto.KeyMeta
	expectedForCombined = append(expectedForCombined, &proto.KeyMeta{Identifier: "sshhostid1"})
	expectedForCombined = append(expectedForCombined, &proto.KeyMeta{Identifier: "sshhostid2"})
	expectedForCombinedMeta := &proto.KeyMetas{Keys: expectedForCombined}
	testcases := map[string]struct {
		KeyUsages      map[string]map[string]bool
		expectKeyMetas *proto.KeyMetas
	}{
		"emptyKeyUsages": {
			expectKeyMetas: expectedEmptyKeyMeta,
		},
		"x509KeyUsages": {
			KeyUsages:      x509keyUsage,
			expectKeyMetas: expectedEmptyKeyMeta,
		},
		"sshKeyUsages": {
			KeyUsages:      sshkeyUsage,
			expectKeyMetas: expectedForSSHMeta,
		},
		"combineKeyUsages": {
			KeyUsages:      combineKeyUsage,
			expectKeyMetas: expectedForCombinedMeta,
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
			var e *empty.Empty
			keyMetas, err := ss.GetHostSSHCertificateAvailableSigningKeys(ctx, e)
			if err != nil {
				t.Fatal(err)
				return
			}
			// we get keyMetas from a map, which are unsorted
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

func TestGetHostSSHCertificateSigningKey(t *testing.T) {
	t.Parallel()
	defaultTimeout := time.Second
	testcases := map[string]struct {
		KeyUsages map[string]map[string]bool
		KeyMeta   *proto.KeyMeta
		timeout   time.Duration
		// if expectedSSHKey set to nil, we are expecting an error while testing
		expectedSSHKey *proto.SSHKey
	}{
		"emptyKeyUsages": {
			KeyMeta:        &proto.KeyMeta{Identifier: "randomid"},
			expectedSSHKey: nil,
		},
		"emptyKeyMeta": {
			expectedSSHKey: nil,
		},
		"sshUsagesWithWrongID": {
			KeyUsages:      sshkeyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "randomId"},
			expectedSSHKey: nil,
		},
		"sshUsagesWithRightID": {
			KeyUsages:      sshkeyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh signing key"},
		},
		"x509KeyUsages": {
			KeyUsages:      x509keyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "x509id"},
			expectedSSHKey: nil,
		},
		"combineKeyUsagesWithTrueIDSet": {
			KeyUsages:      combineKeyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid1"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh signing key"},
		},
		"combineKeyUsagesWithFalseIDSet": {
			KeyUsages:      combineKeyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid2"},
			expectedSSHKey: nil,
		},
		"requestTimeout": {
			KeyUsages:      combineKeyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid1"},
			timeout:        10 * time.Microsecond,
			expectedSSHKey: nil,
		},
	}
	for label, tt := range testcases {
		tt := tt
		label := label
		timeout := defaultTimeout
		if tt.timeout != 0 {
			timeout = tt.timeout
		}
		// the cancel function returned by WithTimeout should be called, not discarded, to avoid a context leak
		ctx, _ := context.WithTimeout(context.Background(), timeout)
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			// bad certsign should return error anyways
			msspBad := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: true}
			ssBad := initMockSigningService(msspBad)
			_, err := ssBad.GetHostSSHCertificateSigningKey(ctx, tt.KeyMeta)
			if err == nil {
				t.Fatalf("in test %v: bad signing service should return error but got nil", label)
			}
			// good certsign
			msspGood := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: false}
			ssGood := initMockSigningService(msspGood)
			key, err := ssGood.GetHostSSHCertificateSigningKey(ctx, tt.KeyMeta)
			if err != nil && tt.expectedSSHKey != nil {
				t.Fatalf("in test %v: not expecting error but got error %v", label, err)
			}
			if err == nil && tt.expectedSSHKey == nil {
				t.Fatalf("in test %v: expecting error but got no error", label)
			}
			if tt.expectedSSHKey != nil {
				if !reflect.DeepEqual(key, tt.expectedSSHKey) {
					t.Errorf("in test %v: cert mismatch: got \n%+v\n, want: \n%+v\n", label, key, tt.expectedSSHKey)
					return
				}
			}
		})
	}
}

func TestPostHostSSHCertificate(t *testing.T) {
	t.Parallel()
	defaultMaxValidity := map[string]uint64{config.X509CertEndpoint: 0}
	defaultTimeout := time.Second
	testcases := map[string]struct {
		KeyUsages   map[string]map[string]bool
		maxValidity map[string]uint64
		validity    uint64
		KeyMeta     *proto.KeyMeta
		// if expectedSSHKey set to nil, we are expecting an error while testing
		expectedSSHKey *proto.SSHKey
		PubKey         string
		KeyID          string
		timeout        time.Duration
	}{
		"emptyKeyUsages": {
			KeyMeta:        &proto.KeyMeta{Identifier: "randomid"},
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"emptyKeyMeta": {
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"sshUsagesWithWrongID": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "randomId"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"sshUsagesWithRightID": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"x509UsagesUsages": {
			KeyUsages:      x509keyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithTrueIDAndInvalidCSR": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "x509id1"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithTrueID": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid1"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithTrueIDAndDsaPubKey": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid1"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodDsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithTrueIDAndEcPubKey": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid1"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodEcdsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithFalseIDSet": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid2"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithInvalidPubKey": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid2"},
			expectedSSHKey: nil,
			PubKey:         "badPubKey",
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithInvalidKeyID": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid2"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          "badKeyId",
		},
		"valid validity": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHHostCertEndpoint: 3600},
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"missing validity": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHHostCertEndpoint: 3600},
			validity:       0,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"validity greater than maxValidity": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHHostCertEndpoint: 3600},
			validity:       3601,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"request timeout": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHHostCertEndpoint: 3600},
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshhostid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
			timeout:        10 * time.Microsecond,
		},
	}
	for label, tt := range testcases {
		tt := tt
		label := label
		timeout := defaultTimeout
		if tt.timeout != 0 {
			timeout = tt.timeout
		}
		// the cancel function returned by WithTimeout should be called, not discarded, to avoid a context leak
		ctx, _ := context.WithTimeout(context.Background(), timeout)
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			// bad certsign should return error anyways
			msspBad := mockSigningServiceParam{KeyUsages: tt.KeyUsages, MaxValidity: tt.maxValidity, sendError: true}
			ssBad := initMockSigningService(msspBad)
			requestBad := &proto.SSHCertificateSigningRequest{KeyMeta: tt.KeyMeta, PublicKey: tt.PubKey, Validity: tt.validity, KeyId: tt.KeyID}
			_, err := ssBad.PostHostSSHCertificate(ctx, requestBad)
			if err == nil {
				t.Fatalf("in test %v: bad signing service should return error but got nil", label)
			}

			// good certsign
			msspGood := mockSigningServiceParam{KeyUsages: tt.KeyUsages, MaxValidity: tt.maxValidity, sendError: false}
			ssGood := initMockSigningService(msspGood)
			requestGood := &proto.SSHCertificateSigningRequest{KeyMeta: tt.KeyMeta, PublicKey: tt.PubKey, Validity: tt.validity, KeyId: tt.KeyID}
			cert, err := ssGood.PostHostSSHCertificate(ctx, requestGood)
			if tt.expectedSSHKey == nil {
				if err == nil {
					t.Errorf("expected error for invalid test %v, got nil", label)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %v, err: %v", label, err)
				}
				if !reflect.DeepEqual(cert, tt.expectedSSHKey) {
					t.Errorf("output doesn't match for %v, got %+v\nwant %+v", label, cert, tt.expectedSSHKey)
				}
			}
		})
	}
}
