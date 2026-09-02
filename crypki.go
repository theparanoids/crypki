// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package crypki

import (
	"context"
	"crypto"
	"crypto/x509"

	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/scheduler"

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

const (
	// Default values for CAconfig.
	defaultCounty         = "ZZ" // Unknown or unspecified country
	defaultCompany        = "CompanyName"
	defaultOrganization   = "OrganizationUnitName"
	defaultCommonName     = "www.example.com"
	defaultValidityPeriod = uint64(730 * 24 * 3600) // 2 years

)

const (
	// SubjectKeyIdSchemeHash derives the CA certificate's SubjectKeyId from the
	// CA public key. The value after the scheme names the hash.
	SubjectKeyIdSchemeHash = "hash"
	// SubjectKeyIdSchemeHex takes the identifier literally from the hex digits
	// that follow. ':', '-' and whitespace between digits are ignored, so a
	// value copied out of `openssl x509 -ext subjectKeyIdentifier` can be pasted
	// in unchanged.
	SubjectKeyIdSchemeHex = "hex"
	// SubjectKeyIdSchemeText takes the identifier literally from the raw UTF-8
	// bytes of the text that follows, which is used exactly as written.
	SubjectKeyIdSchemeText = "text"

	// SubjectKeyIdHashSHA1 names method 1 of RFC 5280, Section 4.2.1.2: the
	// 160-bit SHA-1 hash of the value of the BIT STRING subjectPublicKey.
	SubjectKeyIdHashSHA1 = "sha1"
	// SubjectKeyIdHashSHA256 names method 1 of RFC 7093, Section 2: the leftmost
	// 160 bits of the SHA-256 hash of that same value.
	SubjectKeyIdHashSHA256 = "sha256"

	// SubjectKeyIdSHA1 is the default: it reproduces the identifier that CA
	// certificates generated before this was configurable already carry, so
	// upgrading crypki does not alter an existing trust anchor.
	SubjectKeyIdSHA1 = SubjectKeyIdSchemeHash + ":" + SubjectKeyIdHashSHA1
	// SubjectKeyIdSHA256 is the RFC 7093 counterpart of SubjectKeyIdSHA1.
	SubjectKeyIdSHA256 = SubjectKeyIdSchemeHash + ":" + SubjectKeyIdHashSHA256
)

// CertSign interface contains methods related to signing certificates.
type CertSign interface {
	// GetSSHCertSigningKey returns the SSH signing key of the specified key.
	GetSSHCertSigningKey(ctx context.Context, reqChan chan scheduler.Request, keyIdentifier string) ([]byte, error)
	// SignSSHCert returns an SSH cert signed by the specified key.
	SignSSHCert(ctx context.Context, reqChan chan scheduler.Request, cert *ssh.Certificate, keyIdentifier string, priority proto.Priority) ([]byte, error)
	// GetX509CACert returns the X509 CA cert of the specified key.
	GetX509CACert(ctx context.Context, reqChan chan scheduler.Request, keyIdentifier string) ([]byte, error)
	// SignX509Cert returns an x509 cert signed by the specified key.
	SignX509Cert(ctx context.Context, reqChan chan scheduler.Request, cert *x509.Certificate, keyIdentifier string, priority proto.Priority) ([]byte, error)
	// GetBlobSigningPublicKey returns the public signing key of the specified key that signs the user's data.
	GetBlobSigningPublicKey(ctx context.Context, reqChan chan scheduler.Request, keyIdentifier string) ([]byte, error)
	// SignBlob returns a signature signed by the specified key.
	SignBlob(ctx context.Context, reqChan chan scheduler.Request, digest []byte, opts crypto.SignerOpts, keyIdentifier string, priority proto.Priority) ([]byte, error)
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

	// The validity time period of the CA cert, which is specified in seconds.
	ValidityPeriod uint64 `json:"ValidityPeriod"`

	// SubjectKeyId selects how the CA certificate's SubjectKeyId is determined,
	// as a "scheme:value" pair. "hash:sha1" (the default) and "hash:sha256"
	// derive it from the CA public key; "hex:<digits>" and "text:<string>" take
	// it literally. An empty value means SubjectKeyIdSHA1; an unrecognised one
	// is an error rather than a silent fallback.
	//
	// Changing this for an existing CA changes that CA's key identifier, and
	// with it the authorityKeyIdentifier of every certificate the CA
	// subsequently signs, so treat a change as a trust anchor rotation rather
	// than a configuration tweak.
	SubjectKeyId string `json:"SubjectKeyId"`

	// PKCS#11 device fields.
	Identifier       string `json:"Identifier"`
	KeyLabel         string `json:"KeyLabel"`
	KeyType          int    `json:"KeyType"`
	SignatureAlgo    int    `json:"SignatureAlgo"`
	SlotNumber       int    `json:"SlotNumber"`
	UserPinPath      string `json:"UserPinPath"`
	PKCS11ModulePath string `json:"PKCS11ModulePath"`
}

// LoadDefaults assigns default values to missing required configuration fields.
func (c *CAConfig) LoadDefaults() {
	if c.Country == "" {
		c.Country = defaultCounty
	}
	if c.Organization == "" {
		c.Organization = defaultCompany
	}
	if c.OrganizationalUnit == "" {
		c.OrganizationalUnit = defaultOrganization
	}
	if c.CommonName == "" {
		c.CommonName = defaultCommonName
	}
	if c.ValidityPeriod <= 0 {
		c.ValidityPeriod = defaultValidityPeriod
	}
	if c.SubjectKeyId == "" {
		c.SubjectKeyId = SubjectKeyIdSHA1
	}
}
