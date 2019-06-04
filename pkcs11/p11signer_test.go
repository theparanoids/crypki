package pkcs11

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	p11 "github.com/miekg/pkcs11"
	"github.com/yahoo/crypki/pkcs11/mock_pkcs11"
)

func TestSign(t *testing.T) {
	t.Parallel()

	rsaPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("Failed to generate RSA key: %v", err)
		return
	}

	testcases := map[string]struct {
		data        []byte
		opt         crypto.SignerOpts
		expectError bool
		expectPanic bool
		errMsg      map[string]error
	}{
		"good_SHA1": {
			data:        []byte("good"),
			opt:         crypto.SHA1,
			expectError: false,
		},
		"good_SHA256": {
			data:        []byte("good"),
			opt:         crypto.SHA256,
			expectError: false,
		},
		"good_SHA384": {
			data:        []byte("good"),
			opt:         crypto.SHA384,
			expectError: false,
		},
		"good_SHA512": {
			data:        []byte("good"),
			opt:         crypto.SHA512,
			expectError: false,
		},
		"bad_opt": {
			data:        []byte("not supported hash function"),
			opt:         crypto.MD5,
			expectError: true,
		},
		"bad_SignInit": {
			data:        []byte("SignInit err"),
			opt:         crypto.SHA1,
			expectError: false,
			expectPanic: true,
			errMsg: map[string]error{
				"SignInit": errors.New("SignInit err"),
			},
		},
		"bad_Sign": {
			data:        []byte("Sign err"),
			opt:         crypto.SHA1,
			expectError: false,
			expectPanic: true,
			errMsg: map[string]error{
				"Sign": errors.New("Sign err"),
			},
		},
	}

	for name, tt := range testcases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			defer func() {
				r := recover()
				if tt.expectPanic {
					if r == nil {
						t.Error("expected panic, but got nil")
					}
					return
				} else if r != nil {
					t.Errorf("unexpected panic: %v", r)
					return
				}
			}()
			mockctrl := gomock.NewController(t)
			defer mockctrl.Finish()

			mockCtx := mock_pkcs11.NewMockPKCS11Ctx(mockctrl)
			signer := &p11Signer{mockCtx, 0, 0, 0, 1}

			mockCtx.EXPECT().
				SignInit(gomock.Any(), []*p11.Mechanism{p11.NewMechanism(p11.CKM_RSA_PKCS, nil)}, gomock.Any()).
				Return(tt.errMsg["SignInit"]).
				AnyTimes()

			mockCtx.EXPECT().
				Sign(gomock.Any(), gomock.Any()).
				DoAndReturn(func(_ interface{}, hashed []byte) ([]byte, error) {
					signature, err := rsa.SignPKCS1v15(nil, rsaPrivateKey, 0, hashed)
					if err != nil {
						return nil, err
					}
					return signature, tt.errMsg["Sign"]
				}).
				AnyTimes()

			var digest []byte
			hashFunc := tt.opt.HashFunc()
			if hashFunc != 0 {
				h := hashFunc.New()
				h.Write(tt.data)
				digest = h.Sum(nil)
			} else {
				digest = tt.data
			}

			got, err := signer.Sign(rand.Reader, digest, tt.opt)
			if tt.expectError {
				if err == nil {
					t.Error("expected error, but got nil")
				}
				return
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			err = rsa.VerifyPKCS1v15(&rsaPrivateKey.PublicKey, tt.opt.HashFunc(), digest, got)
			if err != nil {
				t.Errorf("Failed to verify signature: %v", err)
			}
		})
	}

}
