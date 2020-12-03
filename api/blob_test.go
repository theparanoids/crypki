// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.
package api

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"log"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/theparanoids/crypki/proto"
)

func init() {
	log.SetOutput(ioutil.Discard)
}

func TestGetBlobAvailableSigningKeys(t *testing.T) {
	t.Parallel()
	var expectedEmptyKey []*proto.KeyMeta
	expectedEmptyKeyMeta := &proto.KeyMetas{Keys: expectedEmptyKey}
	var expectedForBlob []*proto.KeyMeta
	expectedForBlob = append(expectedForBlob, &proto.KeyMeta{Identifier: "blobid"})
	expectedForBlobMeta := &proto.KeyMetas{Keys: expectedForBlob}
	var expectedForCombined []*proto.KeyMeta
	expectedForCombined = append(expectedForCombined, &proto.KeyMeta{Identifier: "blobid1"})
	expectedForCombined = append(expectedForCombined, &proto.KeyMeta{Identifier: "blobid2"})
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
			expectKeyMetas: expectedEmptyKeyMeta,
		},
		"blobKeyUsage": {
			KeyUsages:      blobkeyUsage,
			expectKeyMetas: expectedForBlobMeta,
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
			keyMetas, err := ss.GetBlobAvailableSigningKeys(ctx, e)
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

func TestGetBlobSigningKey(t *testing.T) {
	t.Parallel()
	defaultTimeout := time.Second
	testcases := map[string]struct {
		KeyUsages map[string]map[string]bool
		KeyMeta   *proto.KeyMeta
		timeout   time.Duration
		// if expectedSSHKey set to nil, we are expecting an error while testing
		expectedKey *proto.PublicKey
	}{
		"emptyKeyUsages": {
			KeyMeta:     &proto.KeyMeta{Identifier: "randomid"},
			expectedKey: nil,
		},
		"emptyKeyMeta": {
			expectedKey: nil,
		},
		"blobUsagesWithWrongID": {
			KeyUsages:   sshkeyUsage,
			KeyMeta:     &proto.KeyMeta{Identifier: "randomId"},
			expectedKey: nil,
		},
		"blobUsagesWithRightID": {
			KeyUsages:   blobkeyUsage,
			KeyMeta:     &proto.KeyMeta{Identifier: "blobid"},
			expectedKey: &proto.PublicKey{Key: "good blob signing key"},
		},
		"sshKeyUsages": {
			KeyUsages:   sshkeyUsage,
			KeyMeta:     &proto.KeyMeta{Identifier: "sshuserid"},
			expectedKey: nil,
		},
		"x509KeyUsages": {
			KeyUsages:   x509keyUsage,
			KeyMeta:     &proto.KeyMeta{Identifier: "x509id"},
			expectedKey: nil,
		},
		"combineKeyUsagesWithTrueIdSet": {
			KeyUsages:   combineKeyUsage,
			KeyMeta:     &proto.KeyMeta{Identifier: "blobid1"},
			expectedKey: &proto.PublicKey{Key: "good blob signing key"},
		},
		"combineKeyUsagesWithFalseIdSet": {
			KeyUsages:   combineKeyUsage,
			KeyMeta:     &proto.KeyMeta{Identifier: "blobid2"},
			expectedKey: nil,
		},
		"requestTimeout": {
			KeyUsages:   combineKeyUsage,
			KeyMeta:     &proto.KeyMeta{Identifier: "blobid1"},
			timeout:     10 * time.Microsecond,
			expectedKey: nil,
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
			_, err := ssBad.GetBlobSigningKey(ctx, tt.KeyMeta)
			if err == nil {
				t.Fatalf("in test %v: bad signing service should return error but got nil", label)
			}
			// good certsign
			msspGood := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: false}
			ssGood := initMockSigningService(msspGood)
			key, err := ssGood.GetBlobSigningKey(ctx, tt.KeyMeta)
			if err != nil && tt.expectedKey != nil {
				t.Fatalf("in test %v: not expecting error but got error %v", label, err)
			}
			if err == nil && tt.expectedKey == nil {
				t.Fatalf("in test %v: expecting error but got no error", label)
			}
			if tt.expectedKey != nil {
				if !reflect.DeepEqual(key, tt.expectedKey) {
					t.Errorf("in test %v: cert mismatch: got \n%+v\n, want: \n%+v\n", label, key, tt.expectedKey)
					return
				}
			}
		})
	}
}

func TestPostSignBlob(t *testing.T) {
	t.Parallel()
	tooLongDigest := "eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA=="
	defaultTimeout := time.Second
	testcases := map[string]struct {
		KeyUsages map[string]map[string]bool
		KeyMeta   *proto.KeyMeta
		// if expectedSSHKey set to nil, we are expecting an error while testing
		expectedSignature *proto.Signature
		Digest            string
		timeout           time.Duration
	}{
		"emptyKeyUsages": {
			KeyMeta:           &proto.KeyMeta{Identifier: "randomid"},
			expectedSignature: nil,
		},
		"emptyKeyMeta": {
			expectedSignature: nil,
		},
		"blobUsagesWithWrongID": {
			KeyUsages:         blobkeyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "randomId"},
			expectedSignature: nil,
		},
		"blobUsages": {
			KeyUsages:         blobkeyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "blobid"},
			expectedSignature: &proto.Signature{Signature: base64.StdEncoding.EncodeToString([]byte("good blob signature"))},
		},
		"tooLongDigest": {
			KeyUsages:         blobkeyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "blobid"},
			Digest:            tooLongDigest,
			expectedSignature: nil,
		},
		"blobUsagesBadDigest": {
			KeyUsages:         blobkeyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "blobid"},
			expectedSignature: nil,
			Digest:            "bad string",
		},
		"sshUsages": {
			KeyUsages:         sshkeyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "sshuserid"},
			expectedSignature: nil,
		},
		"x509Usages": {
			KeyUsages:         x509keyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "blobid"},
			expectedSignature: nil,
		},
		"combineKeyUsagesWithTrueId": {
			KeyUsages:         combineKeyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "blobid1"},
			expectedSignature: &proto.Signature{Signature: base64.StdEncoding.EncodeToString([]byte("good blob signature"))},
		},
		"combineKeyUsagesWithFalseIdSet": {
			KeyUsages:         combineKeyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "blobid2"},
			expectedSignature: nil,
		},
		"requestTimeout": {
			KeyUsages:         combineKeyUsage,
			KeyMeta:           &proto.KeyMeta{Identifier: "blobid1"},
			timeout:           10 * time.Microsecond,
			expectedSignature: nil,
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
			requestBad := &proto.BlobSigningRequest{KeyMeta: tt.KeyMeta, Digest: tt.Digest, HashAlgorithm: proto.HashAlgo_SHA512}
			_, err := ssBad.PostSignBlob(ctx, requestBad)
			if err == nil {
				t.Fatalf("in test %v: bad signing service should return error but got nil", label)
			}

			// good certsign
			msspGood := mockSigningServiceParam{KeyUsages: tt.KeyUsages, sendError: false}
			ssGood := initMockSigningService(msspGood)
			requestGood := &proto.BlobSigningRequest{KeyMeta: tt.KeyMeta, Digest: tt.Digest, HashAlgorithm: proto.HashAlgo_SHA512}
			cert, err := ssGood.PostSignBlob(ctx, requestGood)
			if tt.expectedSignature == nil {
				if err == nil {
					t.Errorf("expected error for invalid test %v, got nil", label)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for %v, err: %v", label, err)
				}
				if !reflect.DeepEqual(cert, tt.expectedSignature) {
					t.Errorf("output doesn't match for %v, got %+v\nwant %+v", label, cert, tt.expectedSignature)
				}
			}
		})
	}
}
