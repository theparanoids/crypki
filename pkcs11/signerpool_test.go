package pkcs11

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	"github.com/golang/mock/gomock"
	p11 "github.com/miekg/pkcs11"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/pkcs11/mock_pkcs11"
)

type badSigner struct{}

func (b *badSigner) Public() crypto.PublicKey {
	return []byte("bad byte")
}

func (b *badSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("bad signer")
}

type MockSignerPool struct {
	signer crypto.Signer
}

func (c MockSignerPool) get() signerWithSignAlgorithm {
	return c
}

func (c MockSignerPool) put(instance signerWithSignAlgorithm) {

}

func (c MockSignerPool) signAlgorithm() crypki.PublicKeyAlgorithm {
	return crypki.RSA
}

func (c MockSignerPool) Public() crypto.PublicKey {
	return c.signer.Public()
}

func (c MockSignerPool) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return c.signer.Sign(rand, digest, opts)
}

func newMockSignerPool(isBad bool) (sPool, error) {
	if isBad {
		return MockSignerPool{&badSigner{}}, nil
	}
	data, err := ioutil.ReadFile("testdata/rsa.key.pem")
	if err != nil {
		return nil, fmt.Errorf("unable to read private key: %v", err)
	}
	decoded, _ := pem.Decode(data)
	key, err := x509.ParsePKCS1PrivateKey(decoded.Bytes)
	if err != nil {
		return nil, fmt.Errorf("unable to parse private key: %v", err)
	}
	return MockSignerPool{key}, nil
}

func TestNewSignerPool(t *testing.T) {
	t.Parallel()

	table := map[string]struct {
		nSigners    int
		pin         string
		slot        uint
		token       string
		objects     []p11.ObjectHandle
		session     p11.SessionHandle
		keyType     crypki.PublicKeyAlgorithm
		expectError bool
		errMsg      map[string]error
	}{
		"good": {
			nSigners:    10,
			keyType:     crypki.UnknownPublicKeyAlgorithm, // should default to RSA
			objects:     []p11.ObjectHandle{1, 2},
			expectError: false,
		},
		"good_zero_signers": {
			nSigners:    0,
			keyType:     crypki.RSA,
			objects:     []p11.ObjectHandle{1, 2},
			expectError: false,
		},
		"bad_OpenSession": {
			nSigners:    10,
			keyType:     crypki.RSA,
			objects:     []p11.ObjectHandle{1, 2},
			expectError: true,
			errMsg: map[string]error{
				"OpenSession": errors.New("failed to open a new Session"),
			},
		},
		"bad_FindObjectsInit": {
			nSigners:    10,
			keyType:     crypki.RSA,
			objects:     []p11.ObjectHandle{1, 2},
			expectError: true,
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
			nSigners:    10,
			keyType:     crypki.RSA,
			objects:     []p11.ObjectHandle{},
			expectError: true,
		},
		"bad_FindObjectsFinal": {
			nSigners:    10,
			keyType:     crypki.RSA,
			objects:     []p11.ObjectHandle{1, 2},
			expectError: true,
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

			ret, err := newSignerPool(mockCtx, tt.nSigners, tt.slot, tt.token, tt.keyType)
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
