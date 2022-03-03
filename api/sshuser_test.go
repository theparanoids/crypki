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

func TestGetUserSSHCertificateAvailableSigningKeys(t *testing.T) {
	t.Parallel()
	var expectedEmptyKey []*proto.KeyMeta
	expectedEmptyKeyMeta := &proto.KeyMetas{Keys: expectedEmptyKey}
	var expectedForSSH []*proto.KeyMeta
	expectedForSSH = append(expectedForSSH, &proto.KeyMeta{Identifier: "sshuserid"})
	expectedForSSHMeta := &proto.KeyMetas{Keys: expectedForSSH}
	var expectedForCombined []*proto.KeyMeta
	expectedForCombined = append(expectedForCombined, &proto.KeyMeta{Identifier: "sshuserid1"})
	expectedForCombined = append(expectedForCombined, &proto.KeyMeta{Identifier: "sshuserid2"})
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
			var e *emptypb.Empty
			keyMetas, err := ss.GetUserSSHCertificateAvailableSigningKeys(ctx, e)
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

func TestGetUserSSHCertificateSigningKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defaultRequestTimeout := map[string]uint{config.SSHUserCertEndpoint: 10}
	testcases := map[string]struct {
		ctx       context.Context
		KeyUsages map[string]map[string]bool
		KeyMeta   *proto.KeyMeta
		// if expectedSSHKey set to nil, we are expecting an error while testing
		expectedSSHKey *proto.SSHKey
		timeout        time.Duration
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
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh signing key"},
		},
		"x509KeyUsages": {
			KeyUsages:      x509keyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "x509id"},
			expectedSSHKey: nil,
		},
		"combineKeyUsagesWithTrueIdSet": {
			KeyUsages:      combineKeyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid1"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh signing key"},
		},
		"combineKeyUsagesWithFalseIdSet": {
			KeyUsages:      combineKeyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid2"},
			expectedSSHKey: nil,
		},
		"requestCancelled": {
			ctx:            cancelCtx,
			KeyUsages:      sshkeyUsage,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: nil,
			timeout:        2 * timeout,
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
			msspBad := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: true, randSleepTimeout: tt.timeout, RequestTimeout: defaultRequestTimeout}
			ssBad := initMockSigningService(msspBad)
			_, err := ssBad.GetUserSSHCertificateSigningKey(tt.ctx, tt.KeyMeta)
			if err == nil {
				t.Fatalf("in test %v: bad signing service should return error but got nil", label)
			}
			// good certsign
			msspGood := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: false, randSleepTimeout: tt.timeout, RequestTimeout: defaultRequestTimeout}
			ssGood := initMockSigningService(msspGood)
			key, err := ssGood.GetUserSSHCertificateSigningKey(tt.ctx, tt.KeyMeta)
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
			if label == "requestCancelled" {
				// this is to test the behavior when client cancels the request while
				// server is still processing the request.
				cancel()
			}
		})
	}
}

func TestPostUserSSHCertificate(t *testing.T) {
	t.Parallel()
	defaultMaxValidity := map[string]uint64{config.SSHUserCertEndpoint: 0}
	defaultRequestTimeout := map[string]uint{config.SSHUserCertEndpoint: 10}
	ctx := context.Background()
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	timeoutCtx, timeCancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer timeCancel()
	testcases := map[string]struct {
		ctx         context.Context
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
			KeyMeta:        &proto.KeyMeta{Identifier: "randomId"},
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"sshUsagesWithRightID": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"x509UsagesUsages": {
			KeyUsages:      x509keyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithTrueIdAndInvalidCSR": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "x509id1"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithTrueId": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid1"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithTrueIdAndDsaPubKey": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid1"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodDsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithTrueIdAndECdsaPubKey": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid1"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodEcdsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithFalseIdSet": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid2"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithInvalidPubKey": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid2"},
			expectedSSHKey: nil,
			PubKey:         "badPubKey",
			KeyID:          testGoodKeyID,
		},
		"combineKeyUsagesWithInvalidKeyId": {
			KeyUsages:      combineKeyUsage,
			maxValidity:    defaultMaxValidity,
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid2"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          "badKeyId",
		},
		"valid validity": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHUserCertEndpoint: 3600},
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: &proto.SSHKey{Key: "good ssh cert"},
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"missing validity": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHUserCertEndpoint: 3600},
			validity:       0,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"validity greater than maxValidity": {
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHUserCertEndpoint: 3600},
			validity:       3601,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
		},
		"requestCancelled": {
			ctx:            cancelCtx,
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHUserCertEndpoint: 3600},
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
			timeout:        2 * timeout,
		},
		"requestTimeout": {
			ctx:            timeoutCtx,
			KeyUsages:      sshkeyUsage,
			maxValidity:    map[string]uint64{config.SSHUserCertEndpoint: 3600},
			validity:       3600,
			KeyMeta:        &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSSHKey: nil,
			PubKey:         testGoodRsaPubKey,
			KeyID:          testGoodKeyID,
			timeout:        2 * timeout,
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
			msspBad := mockSigningServiceParam{KeyUsages: tt.KeyUsages, MaxValidity: tt.maxValidity, sendError: true, randSleepTimeout: tt.timeout, RequestTimeout: defaultRequestTimeout}
			ssBad := initMockSigningService(msspBad)
			requestBad := &proto.SSHCertificateSigningRequest{KeyMeta: tt.KeyMeta, PublicKey: tt.PubKey, Validity: tt.validity, KeyId: tt.KeyID}
			_, err := ssBad.PostUserSSHCertificate(tt.ctx, requestBad)
			if err == nil {
				t.Fatalf("in test %v: bad signing service should return error but got nil", label)
			}

			// good certsign
			msspGood := mockSigningServiceParam{KeyUsages: tt.KeyUsages, MaxValidity: tt.maxValidity, sendError: false, randSleepTimeout: tt.timeout, RequestTimeout: defaultRequestTimeout}
			ssGood := initMockSigningService(msspGood)
			requestGood := &proto.SSHCertificateSigningRequest{KeyMeta: tt.KeyMeta, PublicKey: tt.PubKey, Validity: tt.validity, KeyId: tt.KeyID}
			cert, err := ssGood.PostUserSSHCertificate(tt.ctx, requestGood)
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
			if label == "requestCancelled" {
				// this is to test the behavior when client cancels the request while
				// server is still processing the request.
				cancel()
			}
		})
	}
}
