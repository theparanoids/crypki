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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"errors"
	"fmt"
	"log"
	"math/big"

	p11 "github.com/miekg/pkcs11"
)

// Representation of a *DSA signature
type dsaSignature struct {
	R, S *big.Int
}

// oidDERToCurve maps the hex of the DER encoding of the various curve OIDs to
// the relevant curve parameters
var oidDERToCurve = map[string]elliptic.Curve{
	"06052B81040021":       elliptic.P224(),
	"06082A8648CE3D030107": elliptic.P256(),
	"06052B81040022":       elliptic.P384(),
	"06052B81040023":       elliptic.P521(),
}

//nolint:staticcheck // skipping staticcheck for this function until we move to using crypto/ecdh
func getPublic(point []byte, curve elliptic.Curve) (pub crypto.PublicKey, err error) {
	var ecdsaPub ecdsa.PublicKey

	ecdsaPub.Curve = curve
	pointLength := ecdsaPub.Curve.Params().BitSize/8*2 + 1
	if len(point) != pointLength {
		err = fmt.Errorf("CKA_EC_POINT (%d) does not fit used curve (%d)", len(point), pointLength)
		return
	}
	ecdsaPub.X, ecdsaPub.Y = elliptic.Unmarshal(ecdsaPub.Curve, point[:pointLength])
	if ecdsaPub.X == nil {
		err = errors.New("failed to decode CKA_EC_POINT")
		return
	}
	if !ecdsaPub.Curve.IsOnCurve(ecdsaPub.X, ecdsaPub.Y) {
		err = errors.New("public key is not on curve")
		return
	}

	pub = &ecdsaPub
	return
}

func publicECDSA(s *p11Signer) crypto.PublicKey {
	// Retrieve the curve and public point for the generated public key
	attrs, err := s.context.GetAttributeValue(s.session, s.publicKey, []*p11.Attribute{
		p11.NewAttribute(p11.CKA_EC_PARAMS, nil),
		p11.NewAttribute(p11.CKA_EC_POINT, nil),
	})
	if err != nil {
		log.Printf("publicECDSA: GetAttributeValue failed: %v\n", err)
		return nil
	}
	if len(attrs) < 2 {
		log.Println("publicECDSA: expected two attributes")
		return nil
	}

	curve, ok := oidDERToCurve[fmt.Sprintf("%X", attrs[0].Value)]
	if !ok {
		log.Printf("publicECDSA: unknown curve: %s\n", fmt.Sprintf("%X", attrs[0].Value))
		return nil
	}

	pointBytes := attrs[1].Value
	if pointBytes == nil {
		log.Println("publicECDSA: unable to get EC point")
		return nil
	}
	var pb []byte
	_, err = asn1.Unmarshal(pointBytes, &pb)
	if err != nil {
		log.Printf("publicECDSA: asn1 unmarshal failed: %v\n", err)
		return nil
	}
	pubkey, err := getPublic(pb, curve)
	if err != nil {
		log.Printf("publicECDSA: getPublic failed: %v\n", err)
		return nil
	}
	return pubkey
}

func signDataECDSA(ctx PKCS11Ctx, session p11.SessionHandle, hsmPrivateObject p11.ObjectHandle, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	const MAXBYTES = 262042
	if len(data) > MAXBYTES {
		return nil, errors.New("cannot sign such a large blob of data")
	}

	privateKeyHandle := hsmPrivateObject

	// We only support SHA1, SHA256, SHA384 and SHA512 hash digest algorithms.
	hash := opts.HashFunc()
	mech := make([]*p11.Mechanism, 1)
	switch hash {
	case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		mech[0] = p11.NewMechanism(p11.CKM_ECDSA, nil)
	default:
		return nil, errors.New("unsupported hash algorithm")
	}

	err := ctx.SignInit(session, mech, privateKeyHandle)
	if err != nil {
		return nil, err
	}
	sigBytes, err := ctx.Sign(session, data)
	if err != nil {
		return nil, err
	}
	var sig dsaSignature
	err = sig.unmarshalBytes(sigBytes)
	if err != nil {
		return nil, err
	}
	return sig.marshalDER()
}

// Return the DER encoding of a dsaSignature
func (sig *dsaSignature) marshalDER() ([]byte, error) {
	return asn1.Marshal(*sig)
}

// Populate a dsaSignature from a raw byte sequence
func (sig *dsaSignature) unmarshalBytes(sigBytes []byte) error {
	if len(sigBytes) == 0 {
		return errors.New("malformed signature")
	}
	n := len(sigBytes) / 2
	sig.R, sig.S = new(big.Int), new(big.Int)
	sig.R.SetBytes(sigBytes[:n])
	sig.S.SetBytes(sigBytes[n:])
	return nil
}
