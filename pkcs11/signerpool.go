// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pkcs11

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
)

// sPool is an abstract interface of pool of crypto.Signer
type sPool interface {
	get(ctx context.Context) (signerWithSignAlgorithm, error)
	put(s signerWithSignAlgorithm)
}

type signerWithSignAlgorithm interface {
	crypto.Signer
	publicKeyAlgorithm() x509.PublicKeyAlgorithm
	signAlgorithm() x509.SignatureAlgorithm
}

// SignerPool is a pool of PKCS11 signers
// each key is corresponding with a SignerPool
type SignerPool struct {
	signers chan signerWithSignAlgorithm
}

// newSignerPool initializes a signer pool based on the configuration parameters
func newSignerPool(context PKCS11Ctx, nSigners int, slot uint, keyLabel string, keyType x509.PublicKeyAlgorithm, signatureAlgo x509.SignatureAlgorithm) (sPool, error) {
	signers := make(chan signerWithSignAlgorithm, nSigners)
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

func (c *SignerPool) get(ctx context.Context) (signerWithSignAlgorithm, error) {
	select {
	case signer := <-c.signers:
		return signer, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("request cancelled: %v", ctx.Err())
	}
}

func (c *SignerPool) put(instance signerWithSignAlgorithm) {
	if instance != nil {
		c.signers <- instance
	}
}
