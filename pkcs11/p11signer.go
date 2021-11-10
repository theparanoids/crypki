// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pkcs11

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	p11 "github.com/miekg/pkcs11"
)

type p11Signer struct {
	context       PKCS11Ctx
	session       p11.SessionHandle
	privateKey    p11.ObjectHandle
	publicKey     p11.ObjectHandle
	keyType       x509.PublicKeyAlgorithm
	signatureAlgo x509.SignatureAlgorithm
}

func makeSigner(context PKCS11Ctx, slot uint, tokenLabel string, keyType x509.PublicKeyAlgorithm, signatureAlgo x509.SignatureAlgorithm) (*p11Signer, error) {
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
	case x509.RSA:
		return signDataRSA(s.context, s.session, s.privateKey, msg, opts)
	case x509.ECDSA:
		return signDataECDSA(s.context, s.session, s.privateKey, msg, opts)
	default: // RSA is the default
		return signDataRSA(s.context, s.session, s.privateKey, msg, opts)

	}
}

// Public returns crypto public key.
func (s *p11Signer) Public() crypto.PublicKey {
	switch s.keyType {
	case x509.RSA:
		return publicRSA(s)
	case x509.ECDSA:
		return publicECDSA(s)
	default: // RSA is the default
		return publicRSA(s)
	}
}

// publicKeyAlgorithm returns the public key algorithm of signer.
func (s *p11Signer) publicKeyAlgorithm() x509.PublicKeyAlgorithm {
	return s.keyType
}

// signAlgorithm returns the signature algorithm of signer.
func (s *p11Signer) signAlgorithm() x509.SignatureAlgorithm {
	return s.signatureAlgo
}
