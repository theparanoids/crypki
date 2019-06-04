// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package crypki

import (
	"crypto"
	"crypto/x509"

	"golang.org/x/crypto/ssh"
)

// SignType represents the type of signing to be performed.
type SignType int

const (
	// HostSSHKey indicates that the request should be signed by Host SSHKey slot.
	HostSSHKey SignType = iota
	// X509Key indicates that the request should be signed by X509Key slot.
	X509Key
	// UserSSHKey indicates that the request should be signed by User SSHKey slot.
	UserSSHKey
)

// PublicKeyAlgorithm is used to specify public key algorithm.
type PublicKeyAlgorithm int

// List of supported public key algorithms.
const (
	UnknownPublicKeyAlgorithm PublicKeyAlgorithm = iota
	RSA
	ECDSA
)

// CertSign interface contains methods related to signing certificates.
type CertSign interface {
	// GetSSHCertSigningKey returns the SSH signing key of the specified key.
	GetSSHCertSigningKey(keyIdentifier string) ([]byte, error)
	// SignSSHCert returns an SSH cert signed by the specified key.
	SignSSHCert(cert *ssh.Certificate, keyIdentifier string) ([]byte, error)
	// GetX509CACert returns the X509 CA cert of the specified key.
	GetX509CACert(keyIdentifier string) ([]byte, error)
	// SignX509Cert returns an x509 cert signed by the specified key.
	SignX509Cert(cert *x509.Certificate, keyIdentifier string) ([]byte, error)
	// GetBlobSigningKey returns the public signing key of the specified key that signs the user's data.
	GetBlobSigningPublicKey(keyIdentifier string) ([]byte, error)
	// Sign returns a signature signed by the specified key.
	Sign(digest []byte, opts crypto.SignerOpts, keyIdentifier string) ([]byte, error)
}

// CAConfig represents the configuration params for generating the CA certificate.
type CAConfig struct {
	// Subject fields.
	Country            string `json:"Country"`
	State              string `json:"State"`
	Locality           string `json:"Locality"`
	Organization       string `json:"Organization"`
	OrganizationalUnit string `json:"OrganizationalUnit"`
	CommonName         string `json:"CommonName"`

	// PKCS#11 device fields.
	Identifier       string `json:"Identifier"`
	KeyLabel         string `json:"KeyLabel"`
	SlotNumber       int    `json:"SlotNumber"`
	UserPinPath      string `json:"UserPinPath"`
	PKCS11ModulePath string `json:"PKCS11ModulePath"`
}
