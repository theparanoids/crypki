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
	"context"
	"crypto"
	"errors"
	"io"

	"github.com/theparanoids/crypki"
)

type badSigner struct{}

func (b *badSigner) Public() crypto.PublicKey {
	return []byte("bad byte")
}

func (b *badSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("bad signer")
}

type MockSignerPool struct {
	signer  crypto.Signer
	keyType crypki.PublicKeyAlgorithm
}

func (c MockSignerPool) Get(ctx context.Context) (SignerWithSignAlgorithm, error) {
	select {
	case <-ctx.Done():
		return nil, errors.New("client timeout")
	default:
		return c, nil
	}
}

func (c MockSignerPool) Put(instance SignerWithSignAlgorithm) {

}

func (c MockSignerPool) PublicKeyAlgorithm() crypki.PublicKeyAlgorithm {
	return c.keyType
}

func (c MockSignerPool) SignAlgorithm() crypki.SignatureAlgorithm {
	if c.keyType == crypki.ECDSA {
		return crypki.ECDSAWithSHA256
	}
	return crypki.SHA256WithRSA
}

func (c MockSignerPool) Public() crypto.PublicKey {
	return c.signer.Public()
}

func (c MockSignerPool) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	return c.signer.Sign(rand, digest, opts)
}

func NewMockSignerPool(isBad bool, keyType crypki.PublicKeyAlgorithm, priv crypto.Signer) SPool {
	if isBad {
		return MockSignerPool{&badSigner{}, keyType}
	}
	return MockSignerPool{priv, keyType}
}
