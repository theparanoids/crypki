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
	// SubjectKeyIdHashSHA1 derives the CA certificate's SubjectKeyId with method
	// 1 of RFC 5280, Section 4.2.1.2: the 160-bit SHA-1 hash of the value of the
	// BIT STRING subjectPublicKey.
	SubjectKeyIdHashSHA1 = "SHA1"
	// SubjectKeyIdHashSHA256 derives it with method 1 of RFC 7093, Section 2:
	// the leftmost 160 bits of the SHA-256 hash of that same value.
	SubjectKeyIdHashSHA256 = "SHA256"

	// defaultSubjectKeyIdHash keeps the identifier that CA certificates
	// generated before this was configurable already carry, so that upgrading
	// crypki does not alter an existing trust anchor.
	defaultSubjectKeyIdHash = SubjectKeyIdHashSHA1
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

	// SubjectKeyIdHash selects the hash used to derive the CA certificate's
	// SubjectKeyId: SubjectKeyIdHashSHA1 (the default) or
	// SubjectKeyIdHashSHA256. Changing it for an existing CA changes that CA's
	// key identifier, and with it the authorityKeyIdentifier of every
	// certificate the CA subsequently signs, so treat a change as a trust anchor
	// rotation rather than a configuration tweak.
	SubjectKeyIdHash string `json:"SubjectKeyIdHash"`

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
	if c.SubjectKeyIdHash == "" {
		c.SubjectKeyIdHash = defaultSubjectKeyIdHash
	}
}
