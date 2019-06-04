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
	"time"

	"github.com/yahoo/crypki"
)

// GenCACert creates the CA certificate given signer.
func GenCACert(config *crypki.CAConfig, signer crypto.Signer, hostname string, ips []net.IP, pka crypki.PublicKeyAlgorithm) ([]byte, error) {
	const validityPeriod = uint64(730 * 24 * 3600) // 2 years

	// Backdate start time by one hour as the current system clock may be ahead of other running systems.
	start := uint64(time.Now().Unix())
	end := start + validityPeriod
	start -= 3600

	subj := pkix.Name{
		CommonName:         config.CommonName,
		Country:            []string{config.Country},
		Locality:           []string{config.Locality},
		Province:           []string{config.State},
		Organization:       []string{config.Organization},
		OrganizationalUnit: []string{config.OrganizationalUnit},
	}
	template := &x509.Certificate{
		Subject:               subj,
		SerialNumber:          NewSerial(),
		PublicKeyAlgorithm:    x509.RSA,
		PublicKey:             signer.Public(),
		SignatureAlgorithm:    getSignatureAlgorithm(pka),
		NotBefore:             time.Unix(int64(start), 0),
		NotAfter:              time.Unix(int64(end), 0),
		DNSNames:              []string{hostname},
		IPAddresses:           ips,
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

func NewSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber
}

func getSignatureAlgorithm(pka crypki.PublicKeyAlgorithm) x509.SignatureAlgorithm {
	algo := x509.SHA256WithRSA // default
	switch pka {
	case crypki.RSA:
		algo = x509.SHA256WithRSA
	case crypki.ECDSA:
		algo = x509.ECDSAWithSHA256
	}
	return algo
}
