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
	"fmt"

	"github.com/theparanoids/crypki"
)

// SPool is an abstract interface of pool of crypto.Signer
type SPool interface {
	Get(ctx context.Context) (SignerWithSignAlgorithm, error)
	Put(s SignerWithSignAlgorithm)
}

type SignerWithSignAlgorithm interface {
	crypto.Signer
	PublicKeyAlgorithm() crypki.PublicKeyAlgorithm
	SignAlgorithm() crypki.SignatureAlgorithm
}

// SignerPool is a pool of PKCS11 signers
// each key is corresponding with a SignerPool
type SignerPool struct {
	signers chan SignerWithSignAlgorithm
}

// newSignerPool initializes a signer pool based on the configuration parameters
func newSignerPool(context PKCS11Ctx, nSigners int, slot uint, keyLabel string, keyType crypki.PublicKeyAlgorithm, signatureAlgo crypki.SignatureAlgorithm) (SPool, error) {
	signers := make(chan SignerWithSignAlgorithm, nSigners)
	for i := 0; i < nSigners; i++ {
		signerInstance, err := makeSigner(context, slot, keyLabel, keyType, signatureAlgo)
		if err != nil {
			return &SignerPool{nil}, fmt.Errorf("error making signer: %v", err)
		}
		signers <- signerInstance
	}
	return &SignerPool{
		signers: signers,
	}, nil
}

func (c *SignerPool) Get(ctx context.Context) (SignerWithSignAlgorithm, error) {
	select {
	case signer := <-c.signers:
		return signer, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("request cancelled: %v", ctx.Err())
	}
}

func (c *SignerPool) Put(instance SignerWithSignAlgorithm) {
	c.signers <- instance
}
