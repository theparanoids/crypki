// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package x509cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
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
	template := &x509.Certificate{
		Subject:               subj,
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

func newSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber
}
