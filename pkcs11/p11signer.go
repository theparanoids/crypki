// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pkcs11

import (
	"crypto"
	"errors"
	"fmt"
	"io"

	p11 "github.com/miekg/pkcs11"

	"github.com/theparanoids/crypki"
)

type p11Signer struct {
	context       PKCS11Ctx
	session       p11.SessionHandle
	privateKey    p11.ObjectHandle
	publicKey     p11.ObjectHandle
	keyType       crypki.PublicKeyAlgorithm
	signatureAlgo crypki.SignatureAlgorithm
}

func makeSigner(context PKCS11Ctx, slot uint, tokenLabel string, keyType crypki.PublicKeyAlgorithm, signatureAlgo crypki.SignatureAlgorithm) (*p11Signer, error) {
	session, err := context.OpenSession(slot, p11.CKF_SERIAL_SESSION)
	if err != nil {
		return nil, errors.New("makeSigner: error in OpenSession: " + err.Error())
	}

	privateKey, err := getKey(context, session, tokenLabel, p11.CKO_PRIVATE_KEY)
	if err != nil {
		err = errors.New("makeSigner: error in getPrivateKey: " + err.Error())
		err2 := context.CloseSession(session)
		// append CloseSession error to getPrivateKey error
		if err2 != nil {
			return nil, fmt.Errorf(err.Error() + ", CloseSession: " + err2.Error())
		}
		return nil, err
	}

	publicKey, err := getKey(context, session, tokenLabel, p11.CKO_PUBLIC_KEY)
	if err != nil {
		err = errors.New("makeSigner: error in getPublicKey: " + err.Error())
		err2 := context.CloseSession(session)
		// append CloseSession error to getPublicKey error
		if err2 != nil {
			return nil, fmt.Errorf(err.Error() + ", CloseSession: " + err2.Error())
		}
		return nil, err
	}
	return &p11Signer{context, session, privateKey, publicKey, keyType, signatureAlgo}, nil
}

// Sign signs the data using PKCS11 library. It is part of the crypto.Signer interface.
func (s *p11Signer) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	switch s.keyType {
	case crypki.RSA:
		return signDataRSA(s.context, s.session, s.privateKey, msg, opts)
	case crypki.ECDSA:
		return signDataECDSA(s.context, s.session, s.privateKey, msg, opts)
	default: // RSA is the default
		return signDataRSA(s.context, s.session, s.privateKey, msg, opts)

	}
}

// Public returns crypto public key.
func (s *p11Signer) Public() crypto.PublicKey {
	switch s.keyType {
	case crypki.RSA:
		return publicRSA(s)
	case crypki.ECDSA:
		return publicECDSA(s)
	default: // RSA is the default
		return publicRSA(s)
	}
}

// PublicKeyAlgorithm returns the public key algorithm of signer.
func (s *p11Signer) PublicKeyAlgorithm() crypki.PublicKeyAlgorithm {
	return s.keyType
}

// SignAlgorithm returns the signature algorithm of signer.
func (s *p11Signer) SignAlgorithm() crypki.SignatureAlgorithm {
	return s.signatureAlgo
}
