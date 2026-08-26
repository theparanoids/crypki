// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package x509cert

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/theparanoids/crypki"
)

// GenCACert creates the CA certificate given signer.
func GenCACert(config *crypki.CAConfig, signer crypto.Signer, hostname string, ips []net.IP, uris []*url.URL, pka x509.PublicKeyAlgorithm, sa x509.SignatureAlgorithm) ([]byte, error) {
	// Backdate start time by one hour as the current system clock may be ahead of other running systems.
	start := uint64(time.Now().Unix())
	end := start + config.ValidityPeriod
	start -= 3600
	var country, locality, province, org, orgUnit, dnsNames []string
	if config.Country != "" {
		country = []string{config.Country}
	}
	if config.Locality != "" {
		locality = []string{config.Locality}
	}
	if config.State != "" {
		province = []string{config.State}
	}
	if config.Organization != "" {
		org = []string{config.Organization}
	}
	if config.OrganizationalUnit != "" {
		orgUnit = []string{config.OrganizationalUnit}
	}
	if hostname != "" {
		dnsNames = []string{hostname}
	}

	subj := pkix.Name{
		CommonName:         config.CommonName,
		Country:            country,
		Locality:           locality,
		Province:           province,
		Organization:       org,
		OrganizationalUnit: orgUnit,
	}
	skid, err := subjectKeyID(signer.Public(), config.SubjectKeyIdHash)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		Subject:               subj,
		SubjectKeyId:          skid,
		SerialNumber:          newSerial(),
		PublicKeyAlgorithm:    pka,
		PublicKey:             signer.Public(),
		SignatureAlgorithm:    sa,
		NotBefore:             time.Unix(int64(start), 0),
		NotAfter:              time.Unix(int64(end), 0),
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		URIs:                  uris,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("unable to sign x509 cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), nil
}

// subjectKeyID derives a key identifier from pub with the hash named by
// hashName: crypki.SubjectKeyIdHashSHA1 (method 1 of RFC 5280, Section
// 4.2.1.2), crypki.SubjectKeyIdHashSHA256 (method 1 of RFC 7093, Section 2), or
// empty for the SHA-1 default.
//
// x509.CreateCertificate can fill in a missing SubjectKeyId on its own, but
// which algorithm it uses depends on the Go release the binary was built with:
// Go 1.25 switched from the SHA-1 of RFC 5280 to the truncated SHA-256 of RFC
// 7093. A CA certificate's key identifier is part of the trust anchor's
// identity -- CreateCertificate copies it into the authorityKeyIdentifier of
// every certificate the CA goes on to sign, and verifiers match that back to
// the CA when building a chain -- so letting it change with the toolchain
// silently invalidates the chains an existing deployment already trusts.
// Deriving it here makes it a property of the key and the configuration rather
// than of the build.
//
// The default is applied here rather than left to CAConfig.LoadDefaults, which
// cmd/gen-cacert does not call.
func subjectKeyID(pub crypto.PublicKey, hashName string) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal public key: %v", err)
	}
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &spki); err != nil {
		return nil, fmt.Errorf("unable to parse public key: %v", err)
	}
	switch strings.ToUpper(strings.TrimSpace(hashName)) {
	case "", crypki.SubjectKeyIdHashSHA1:
		sum := sha1.Sum(spki.SubjectPublicKey.Bytes)
		return sum[:], nil
	case crypki.SubjectKeyIdHashSHA256:
		sum := sha256.Sum256(spki.SubjectPublicKey.Bytes)
		return sum[:20], nil
	default:
		return nil, fmt.Errorf("unknown SubjectKeyIdHash %q, want %q or %q", hashName, crypki.SubjectKeyIdHashSHA1, crypki.SubjectKeyIdHashSHA256)
	}
}

func newSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber
}
