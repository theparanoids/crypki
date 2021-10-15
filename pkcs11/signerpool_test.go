// Copyright 2021 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pkcs11

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	p11 "github.com/miekg/pkcs11"
	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/pkcs11/mock_pkcs11"
)

func TestNewSignerPool(t *testing.T) {
	t.Parallel()

	table := map[string]struct {
		nSigners      int
		pin           string
		slot          uint
		token         string
		objects       []p11.ObjectHandle
		session       p11.SessionHandle
		keyType       crypki.PublicKeyAlgorithm
		signatureAlgo crypki.SignatureAlgorithm
		expectError   bool
		errMsg        map[string]error
	}{
		"good": {
			nSigners:      10,
			keyType:       crypki.UnknownPublicKeyAlgorithm, // should default to RSA
			signatureAlgo: crypki.UnknownSignatureAlgorithm, // should default to SHA256WithRSA
			objects:       []p11.ObjectHandle{1, 2},
			expectError:   false,
		},
		"good_ec": {
			nSigners:      10,
			keyType:       crypki.ECDSA,
			signatureAlgo: crypki.ECDSAWithSHA384,
			objects:       []p11.ObjectHandle{1, 2},
			expectError:   false,
		},
		"good_zero_signers": {
			nSigners:      0,
			keyType:       crypki.RSA,
			signatureAlgo: crypki.SHA256WithRSA,
			objects:       []p11.ObjectHandle{1, 2},
			expectError:   false,
		},
		"bad_OpenSession": {
			nSigners:      10,
			keyType:       crypki.RSA,
			signatureAlgo: crypki.SHA256WithRSA,
			objects:       []p11.ObjectHandle{1, 2},
			expectError:   true,
			errMsg: map[string]error{
				"OpenSession": errors.New("failed to open a new Session"),
			},
		},
		"bad_FindObjectsInit": {
			nSigners:      10,
			keyType:       crypki.RSA,
			signatureAlgo: crypki.SHA256WithRSA,
			objects:       []p11.ObjectHandle{1, 2},
			expectError:   true,
			errMsg: map[string]error{
				"FindObjectsInit": errors.New("failed to FindObjectsInit"),
			},
		},
		"bad_FindObjects": {
			nSigners:    10,
			objects:     []p11.ObjectHandle{1, 2},
			expectError: true,
			errMsg: map[string]error{
				"FindObjects": errors.New("failed to FindObjects"),
			},
		},
		"bad_no_objects": {
			nSigners:      10,
			keyType:       crypki.RSA,
			signatureAlgo: crypki.SHA256WithRSA,
			objects:       []p11.ObjectHandle{},
			expectError:   true,
		},
		"bad_FindObjectsFinal": {
			nSigners:      10,
			keyType:       crypki.RSA,
			signatureAlgo: crypki.SHA256WithRSA,
			objects:       []p11.ObjectHandle{1, 2},
			expectError:   true,
			errMsg: map[string]error{
				"FindObjectsFinal": errors.New("failed to FindObjectsFinal"),
			},
		},
	}

	for name, tt := range table {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			mockctrl := gomock.NewController(t)
			defer mockctrl.Finish()

			mockCtx := mock_pkcs11.NewMockPKCS11Ctx(mockctrl)
			mockCtx.EXPECT().
				OpenSession(tt.slot, gomock.Any()).
				Return(tt.session, tt.errMsg["OpenSession"]).
				AnyTimes()

			mockCtx.EXPECT().
				Login(tt.session, p11.CKU_USER, gomock.Any()).
				Return(tt.errMsg["Login"]).
				AnyTimes()

			mockCtx.EXPECT().
				CloseSession(tt.session).
				Return(tt.errMsg["CloseSession"]).
				AnyTimes()

			mockCtx.EXPECT().
				FindObjectsInit(tt.session, gomock.Any()).
				Return(tt.errMsg["FindObjectsInit"]).
				AnyTimes()

			mockCtx.EXPECT().
				FindObjects(tt.session, gomock.Any()).
				Return(tt.objects, true, tt.errMsg["FindObjects"]).
				AnyTimes()

			mockCtx.EXPECT().
				FindObjectsFinal(tt.session).
				Return(tt.errMsg["FindObjectsFinal"]).
				AnyTimes()

			ret, err := newSignerPool(mockCtx, tt.nSigners, tt.slot, tt.token, tt.keyType, tt.signatureAlgo)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
				return
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			got, ok := ret.(*SignerPool)
			if !ok {
				t.Errorf("Convert type error: %v", err)
				return
			}

			if len(got.signers) != tt.nSigners {
				t.Errorf("Expect %v Signers, but got %v", tt.nSigners, len(got.signers))
				return
			}
		})
	}
}
