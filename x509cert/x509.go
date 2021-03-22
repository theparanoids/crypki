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

	"github.com/theparanoids/crypki"
)

// GenCACert creates the CA certificate given signer.
func GenCACert(config *crypki.CAConfig, signer crypto.Signer, hostname string, ips []net.IP, pka crypki.PublicKeyAlgorithm, sa crypki.SignatureAlgorithm) ([]byte, error) {
	// Backdate start time by one hour as the current system clock may be ahead of other running systems.
	start := uint64(time.Now().Unix())
	end := start + config.ValidityPeriod
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
		SerialNumber:          newSerial(),
		PublicKeyAlgorithm:    getPublicKeyAlgorithm(pka),
		PublicKey:             signer.Public(),
		SignatureAlgorithm:    GetSignatureAlgorithm(pka, sa),
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

func newSerial() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	return serialNumber
}

// GetSignatureAlgorithm returns x509 Signature algorithm corresponding to either the crypki signature algorithm passed
// else based on the public key algorithm it chooses the default signature algorithm.
// Currently the signature algorithm CRYPKI supports is SHA256WithRSA, ECDSAWithSHA256, ECDSAWithSHA384.
func GetSignatureAlgorithm(pka crypki.PublicKeyAlgorithm, sa crypki.SignatureAlgorithm) x509.SignatureAlgorithm {
	if sa != crypki.UnknownSignatureAlgorithm {
		switch sa {
		case crypki.SHA256WithRSA:
			return x509.SHA256WithRSA
		case crypki.ECDSAWithSHA256:
			return x509.ECDSAWithSHA256
		case crypki.ECDSAWithSHA384:
			return x509.ECDSAWithSHA384
		}
	}
	// if signature algo doesn't match above use the default values based on public key algo
	algo := x509.SHA256WithRSA // default
	switch pka {
	case crypki.RSA:
		algo = x509.SHA256WithRSA
	case crypki.ECDSA:
		algo = x509.ECDSAWithSHA384
	}
	return algo
}

func getPublicKeyAlgorithm(pka crypki.PublicKeyAlgorithm) x509.PublicKeyAlgorithm {
	algo := x509.RSA
	switch pka {
	case crypki.RSA:
		algo = x509.RSA
	case crypki.ECDSA:
		algo = x509.ECDSA
	}
	return algo
}
