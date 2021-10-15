// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

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
