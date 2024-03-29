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
}
