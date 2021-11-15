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
	"crypto/rsa"
	"errors"
	"math/big"

	p11 "github.com/miekg/pkcs11"
)

// prefixes copied from https://github.com/golang/go/blob/master/src/crypto/rsa/pkcs1v15.go#L208-L217
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.SHA1:   {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA256: {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384: {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512: {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
}

func publicRSA(s *p11Signer) crypto.PublicKey {
	attrTemplate := []*p11.Attribute{
		p11.NewAttribute(p11.CKA_MODULUS, nil),
		p11.NewAttribute(p11.CKA_PUBLIC_EXPONENT, nil),
	}
	attr, err := s.context.GetAttributeValue(s.session, s.publicKey, attrTemplate)
	if err != nil {
		panic("Error returning public key: " + err.Error())
	}
	gotMod, gotExp := false, false
	rsapubkey := new(rsa.PublicKey)
	for _, a := range attr {
		switch a.Type {
		case p11.CKA_MODULUS:
			rsapubkey.N = big.NewInt(0).SetBytes(a.Value)
			gotMod = true
		case p11.CKA_PUBLIC_EXPONENT:
			rsapubkey.E = int(big.NewInt(0).SetBytes(a.Value).Int64())
			gotExp = true
		}
	}
	if !gotExp || !gotMod {
		panic("unable to retrieve modulus and/or exponent")
	}
	return rsapubkey
}

func signDataRSA(ctx PKCS11Ctx, session p11.SessionHandle, hsmPrivateObject p11.ObjectHandle, data []byte, opts crypto.SignerOpts) ([]byte, error) {
	const MAXBYTES = 262042
	if len(data) > MAXBYTES {
		return nil, errors.New("cannot sign such a large blob of data")
	}

	privateKeyHandle := hsmPrivateObject

	var buf []byte
	// We only support SHA1, SHA256, SHA384 and SHA512 hash digest algorithms.
	// If the data is the digest from one of those algorithms,
	// we need to prepend the hash identifier before generating
	// the signature for the buffer.
	hash := opts.HashFunc()
	mech := make([]*p11.Mechanism, 1)
	switch hash {
	case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		buf = append(hashPrefixes[hash], data...)
		mech[0] = p11.NewMechanism(p11.CKM_RSA_PKCS, nil)
	default:
		return nil, errors.New("unsupported hash algorithm")
	}

	err := ctx.SignInit(session, mech, privateKeyHandle)
	if err != nil {
		panic(err)
	}
	signed, err := ctx.Sign(session, buf)
	if err != nil {
		panic(err)
	}
	return signed, err
}
