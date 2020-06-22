// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pkcs11

import (
	"crypto"
	"fmt"

	"github.com/theparanoids/crypki"
)

// sPool is an abstract interface of pool of crypto.Signer
type sPool interface {
	get() signerWithSignAlgorithm
	put(s signerWithSignAlgorithm)
}

type signerWithSignAlgorithm interface {
	crypto.Signer
	signAlgorithm() crypki.PublicKeyAlgorithm
}

// SignerPool is a pool of PKCS11 signers
// each key is corresponding with a SignerPool
type SignerPool struct {
	signers chan signerWithSignAlgorithm
}

// newSignerPool initializes a signer pool based on the configuration parameters
func newSignerPool(context PKCS11Ctx, nSigners int, slot uint, tokenLabel string, keyType crypki.PublicKeyAlgorithm) (sPool, error) {
	signers := make(chan signerWithSignAlgorithm, nSigners)
	for i := 0; i < nSigners; i++ {
		signerInstance, err := makeSigner(context, slot, tokenLabel, keyType)
		if err != nil {
			return &SignerPool{nil}, fmt.Errorf("error making signer: %v", err)
		}
		signers <- signerInstance
	}
	return &SignerPool{
		signers: signers,
	}, nil
}

func (c *SignerPool) get() signerWithSignAlgorithm {
	return <-c.signers
}

func (c *SignerPool) put(instance signerWithSignAlgorithm) {
	c.signers <- instance
}
