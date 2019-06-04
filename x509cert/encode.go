// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package x509cert

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/yahoo/crypki/proto"
)

// DecodeRequest process the X509CertificateSigningRequest and returns an (unsigned) x509 certificate.
func DecodeRequest(req *proto.X509CertificateSigningRequest) (*x509.Certificate, error) {
	csr, err := decodeCSR(req.GetCsr())
	if err != nil {
		return nil, fmt.Errorf("unable to decode CSR: %v", err)
	}

	x509ExtKeyUsage, err := getX509ExtKeyUsage(req.GetExtKeyUsage())
	if err != nil {
		return nil, fmt.Errorf("invalid ExtKeyUsage: %v", err)
	}
	// Backdate start time by one hour as the current system clock may be ahead of other running systems.
	start := uint64(time.Now().Unix())
	end := start + req.GetValidity()
	start -= 3600

	// Construct an (unsigned) x509 certificate.
	return &x509.Certificate{
		Subject:               csr.Subject,
		SerialNumber:          NewSerial(),
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             time.Unix(int64(start), 0),
		NotAfter:              time.Unix(int64(end), 0),
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           x509ExtKeyUsage,
		BasicConstraintsValid: true,
	}, nil
}

// getX509ExtKeyUsage returns []x509.ExtKeyUsage from []int32
func getX509ExtKeyUsage(x509ExtKeyUsages []int32) ([]x509.ExtKeyUsage, error) {
	if len(x509ExtKeyUsages) == 0 {
		return []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, nil
	}
	var x509ExtKeyUsagesRet []x509.ExtKeyUsage
	for _, x509ExtKeyUsage := range x509ExtKeyUsages {
		// validate if extUsage falls under https://golang.org/src/crypto/x509/x509.go?s=18153:18173#L558
		if x509ExtKeyUsage < 0 || x509ExtKeyUsage > 11 {
			return nil, fmt.Errorf("invalid x509 ExtKeyUsage value: %d, valid values are [0,1,...11]", x509ExtKeyUsage)
		}
		x509ExtKeyUsagesRet = append(x509ExtKeyUsagesRet, x509.ExtKeyUsage(x509ExtKeyUsage))
	}
	return x509ExtKeyUsagesRet, nil
}

// decodeCSR decodes CSR and returns x509 CertificateRequest struct.
func decodeCSR(csr string) (*x509.CertificateRequest, error) {
	var derBytes []byte
	block, _ := pem.Decode([]byte(csr))
	if block == nil {
		return nil, errors.New("empty pem")
	}
	derBytes = block.Bytes
	req, err := x509.ParseCertificateRequest(derBytes)
	if err != nil {
		return nil, err
	}
	err = req.CheckSignature()
	if err != nil {
		return nil, err
	}
	return req, nil
}
