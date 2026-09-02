// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pkcs11

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	"github.com/golang/mock/gomock"
	p11 "github.com/miekg/pkcs11"
	"github.com/theparanoids/crypki/pkcs11/mock_pkcs11"
)

// ecParams returns the DER encoding of the named curve OID, which is what an
// HSM reports in CKA_EC_PARAMS.
func ecParams(t *testing.T, oidDER string) []byte {
	t.Helper()
	b, err := hex.DecodeString(oidDER)
	if err != nil {
		t.Fatalf("bad test fixture %q: %v", oidDER, err)
	}
	return b
}

// ecPoint returns the DER OCTET STRING wrapping of an uncompressed EC point,
// which is what an HSM reports in CKA_EC_POINT.
func ecPoint(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()
	//nolint:staticcheck // matches the elliptic.Unmarshal call in publicECDSA
	raw := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	der, err := asn1.Marshal(raw)
	if err != nil {
		t.Fatalf("failed to marshal EC point: %v", err)
	}
	return der
}

func newMockSigner(t *testing.T, keyType x509.PublicKeyAlgorithm, signatureAlgo x509.SignatureAlgorithm, attrs []*p11.Attribute, err error) *p11Signer {
	t.Helper()
	mockctrl := gomock.NewController(t)
	t.Cleanup(mockctrl.Finish)

	mockCtx := mock_pkcs11.NewMockPKCS11Ctx(mockctrl)
	mockCtx.EXPECT().
		GetAttributeValue(gomock.Any(), gomock.Any(), gomock.Any()).
		Return(attrs, err).
		AnyTimes()
	return &p11Signer{mockCtx, 0, 0, 0, keyType, signatureAlgo}
}

func TestP11SignerAlgorithms(t *testing.T) {
	t.Parallel()

	signer := &p11Signer{nil, 0, 0, 0, x509.ECDSA, x509.ECDSAWithSHA384}
	if got := signer.publicKeyAlgorithm(); got != x509.ECDSA {
		t.Errorf("publicKeyAlgorithm() = %v, want %v", got, x509.ECDSA)
	}
	if got := signer.signAlgorithm(); got != x509.ECDSAWithSHA384 {
		t.Errorf("signAlgorithm() = %v, want %v", got, x509.ECDSAWithSHA384)
	}
}

func TestPublicRSA(t *testing.T) {
	t.Parallel()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	modulus := privateKey.PublicKey.N.Bytes()
	exponent := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()

	testcases := map[string]struct {
		attrs   []*p11.Attribute
		attrErr error
		want    *rsa.PublicKey
	}{
		"modulus and exponent are assembled into a public key": {
			attrs: []*p11.Attribute{
				p11.NewAttribute(p11.CKA_MODULUS, modulus),
				p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, exponent),
			},
			want: &privateKey.PublicKey,
		},
		"a GetAttributeValue error yields no key": {
			attrErr: errors.New("GetAttributeValue failed"),
		},
		"a missing exponent yields no key": {
			attrs: []*p11.Attribute{p11.NewAttribute(p11.CKA_MODULUS, modulus)},
		},
		"a missing modulus yields no key": {
			attrs: []*p11.Attribute{p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, exponent)},
		},
		"an unrelated attribute yields no key": {
			attrs: []*p11.Attribute{p11.NewAttribute(p11.CKA_LABEL, []byte("x509-key"))},
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			signer := newMockSigner(t, x509.RSA, x509.SHA256WithRSA, tt.attrs, tt.attrErr)

			// Public() dispatches on the key type, so it and publicRSA are
			// expected to agree.
			for name, got := range map[string]interface{}{
				"publicRSA": publicRSA(signer),
				"Public":    signer.Public(),
			} {
				if tt.want == nil {
					if got != nil {
						t.Errorf("%s() = %v, want nil", name, got)
					}
					continue
				}
				pub, ok := got.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("%s() returned %T, want *rsa.PublicKey", name, got)
				}
				if !pub.Equal(tt.want) {
					t.Errorf("%s() = %v, want %v", name, pub, tt.want)
				}
			}
		})
	}
}

func TestPublicECDSA(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	p256Params := ecParams(t, "06082A8648CE3D030107")
	point := ecPoint(t, &privateKey.PublicKey)

	testcases := map[string]struct {
		attrs   []*p11.Attribute
		attrErr error
		want    *ecdsa.PublicKey
	}{
		"curve params and point are assembled into a public key": {
			attrs: []*p11.Attribute{
				p11.NewAttribute(p11.CKA_EC_PARAMS, p256Params),
				p11.NewAttribute(p11.CKA_EC_POINT, point),
			},
			want: &privateKey.PublicKey,
		},
		"a GetAttributeValue error yields no key": {
			attrErr: errors.New("GetAttributeValue failed"),
		},
		"fewer than two attributes yields no key": {
			attrs: []*p11.Attribute{p11.NewAttribute(p11.CKA_EC_PARAMS, p256Params)},
		},
		"an unknown curve yields no key": {
			attrs: []*p11.Attribute{
				p11.NewAttribute(p11.CKA_EC_PARAMS, ecParams(t, "06052B81040009")),
				p11.NewAttribute(p11.CKA_EC_POINT, point),
			},
		},
		"a nil point yields no key": {
			attrs: []*p11.Attribute{
				p11.NewAttribute(p11.CKA_EC_PARAMS, p256Params),
				p11.NewAttribute(p11.CKA_EC_POINT, nil),
			},
		},
		"a point that is not DER yields no key": {
			attrs: []*p11.Attribute{
				p11.NewAttribute(p11.CKA_EC_PARAMS, p256Params),
				p11.NewAttribute(p11.CKA_EC_POINT, []byte{0xff, 0xff}),
			},
		},
		"a point that does not fit the curve yields no key": {
			attrs: []*p11.Attribute{
				// P-384 params against a P-256 sized point.
				p11.NewAttribute(p11.CKA_EC_PARAMS, ecParams(t, "06052B81040022")),
				p11.NewAttribute(p11.CKA_EC_POINT, point),
			},
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			signer := newMockSigner(t, x509.ECDSA, x509.ECDSAWithSHA256, tt.attrs, tt.attrErr)

			for name, got := range map[string]interface{}{
				"publicECDSA": publicECDSA(signer),
				"Public":      signer.Public(),
			} {
				if tt.want == nil {
					if got != nil {
						t.Errorf("%s() = %v, want nil", name, got)
					}
					continue
				}
				pub, ok := got.(*ecdsa.PublicKey)
				if !ok {
					t.Fatalf("%s() returned %T, want *ecdsa.PublicKey", name, got)
				}
				if !pub.Equal(tt.want) {
					t.Errorf("%s() = %v, want %v", name, pub, tt.want)
				}
			}
		})
	}
}

func TestGetPublic(t *testing.T) {
	t.Parallel()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	//nolint:staticcheck // matches the elliptic.Unmarshal call in getPublic
	point := elliptic.Marshal(elliptic.P256(), privateKey.PublicKey.X, privateKey.PublicKey.Y)

	offCurve := make([]byte, len(point))
	copy(offCurve, point)
	// Flip a bit in the Y coordinate so the point decodes but is not on the
	// curve. Y ends at the last byte, so the low bit of that is enough.
	offCurve[len(offCurve)-1] ^= 0x01

	testcases := map[string]struct {
		point   []byte
		curve   elliptic.Curve
		wantErr bool
	}{
		"an uncompressed point on the curve decodes": {
			point: point,
			curve: elliptic.P256(),
		},
		"a point of the wrong length is rejected": {
			point:   point,
			curve:   elliptic.P384(),
			wantErr: true,
		},
		"an all zero point is rejected": {
			point:   make([]byte, len(point)),
			curve:   elliptic.P256(),
			wantErr: true,
		},
		"a point off the curve is rejected": {
			point:   offCurve,
			curve:   elliptic.P256(),
			wantErr: true,
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			pub, err := getPublic(tt.point, tt.curve)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("getPublic() = %v, want an error", pub)
				}
				return
			}
			if err != nil {
				t.Fatalf("getPublic() returned error: %v", err)
			}
			got, ok := pub.(*ecdsa.PublicKey)
			if !ok {
				t.Fatalf("getPublic() returned %T, want *ecdsa.PublicKey", pub)
			}
			if !got.Equal(&privateKey.PublicKey) {
				t.Errorf("getPublic() = %v, want %v", got, &privateKey.PublicKey)
			}
		})
	}
}
