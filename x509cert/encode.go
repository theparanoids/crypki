// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package x509cert

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/theparanoids/crypki/proto"
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
		SerialNumber:          newSerial(),
		PublicKeyAlgorithm:    csr.PublicKeyAlgorithm,
		PublicKey:             csr.PublicKey,
		SignatureAlgorithm:    csr.SignatureAlgorithm,
		NotBefore:             time.Unix(int64(start), 0),
		NotAfter:              time.Unix(int64(end), 0),
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtraExtensions:       x509ExtKeyUsage,
		BasicConstraintsValid: true,
	}, nil
}

// extKeyUsageToExtension returns []pkix.Extension from []x509.ExtKeyUsage.
// This allows us to add EKU with a specific Critical bit instead of the default false value.

func extKeyUsageToExtension(extKeyUsage []x509.ExtKeyUsage) ([]pkix.Extension, error) {

	var critMap = map[x509.ExtKeyUsage]bool{
		x509.ExtKeyUsageAny:             false,
		x509.ExtKeyUsageServerAuth:      false,
		x509.ExtKeyUsageClientAuth:      false,
		x509.ExtKeyUsageCodeSigning:     false,
		x509.ExtKeyUsageEmailProtection: false,
		x509.ExtKeyUsageIPSECEndSystem:  false,
		x509.ExtKeyUsageIPSECTunnel:     false,
		x509.ExtKeyUsageIPSECUser:       false,
		// https://www.ietf.org/rfc/rfc3161.txt "id-kp-timeStamping.  This extension MUST be critical."
		x509.ExtKeyUsageTimeStamping:                   true,
		x509.ExtKeyUsageOCSPSigning:                    false,
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     false,
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      false,
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: false,
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     false,
	}

	// values copied from Go crypto/x509 library - https://cs.opensource.google/go/go/+/refs/tags/go1.20.6:src/crypto/x509/x509.go;l=599
	var (
		oidExtensionExtendedKeyUsage                 = asn1.ObjectIdentifier{2, 5, 29, 37}
		oidExtKeyUsageAny                            = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
		oidExtKeyUsageServerAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
		oidExtKeyUsageClientAuth                     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
		oidExtKeyUsageCodeSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
		oidExtKeyUsageEmailProtection                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
		oidExtKeyUsageIPSECEndSystem                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
		oidExtKeyUsageIPSECTunnel                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
		oidExtKeyUsageIPSECUser                      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
		oidExtKeyUsageTimeStamping                   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
		oidExtKeyUsageOCSPSigning                    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
		oidExtKeyUsageMicrosoftServerGatedCrypto     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
		oidExtKeyUsageNetscapeServerGatedCrypto      = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
		oidExtKeyUsageMicrosoftCommercialCodeSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 1, 22}
		oidExtKeyUsageMicrosoftKernelCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 61, 1, 1}
	)
	var extCritTrue, extCritFalse []asn1.ObjectIdentifier
	var extensions []pkix.Extension
	for _, eku := range extKeyUsage {
		var oid asn1.ObjectIdentifier
		switch eku {
		case x509.ExtKeyUsageAny:
			oid = oidExtKeyUsageAny
		case x509.ExtKeyUsageServerAuth:
			oid = oidExtKeyUsageServerAuth
		case x509.ExtKeyUsageClientAuth:
			oid = oidExtKeyUsageClientAuth
		case x509.ExtKeyUsageCodeSigning:
			oid = oidExtKeyUsageCodeSigning
		case x509.ExtKeyUsageEmailProtection:
			oid = oidExtKeyUsageEmailProtection
		case x509.ExtKeyUsageIPSECEndSystem:
			oid = oidExtKeyUsageIPSECEndSystem
		case x509.ExtKeyUsageIPSECTunnel:
			oid = oidExtKeyUsageIPSECTunnel
		case x509.ExtKeyUsageIPSECUser:
			oid = oidExtKeyUsageIPSECUser
		case x509.ExtKeyUsageTimeStamping:
			oid = oidExtKeyUsageTimeStamping
		case x509.ExtKeyUsageOCSPSigning:
			oid = oidExtKeyUsageOCSPSigning
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			oid = oidExtKeyUsageMicrosoftServerGatedCrypto
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			oid = oidExtKeyUsageNetscapeServerGatedCrypto
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			oid = oidExtKeyUsageMicrosoftCommercialCodeSigning
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			oid = oidExtKeyUsageMicrosoftKernelCodeSigning
		}
		// Group all EKUs based on whether Critical flag is set.
		// Each set forms a separate pkix.Extension.
		if critMap[eku] {
			extCritTrue = append(extCritTrue, oid)
		} else {
			extCritFalse = append(extCritFalse, oid)
		}
	}
	if len(extCritTrue) != 0 {
		oidM, err := asn1.Marshal(extCritTrue)
		if err != nil {
			return nil, err
		}
		extension := pkix.Extension{
			Id:       oidExtensionExtendedKeyUsage,
			Critical: true,
			Value:    oidM,
		}
		extensions = append(extensions, extension)
	}
	if len(extCritFalse) != 0 {
		oidM, err := asn1.Marshal(extCritFalse)
		if err != nil {
			return nil, err
		}
		extension := pkix.Extension{
			Id:       oidExtensionExtendedKeyUsage,
			Critical: false,
			Value:    oidM,
		}
		extensions = append(extensions, extension)
	}
	return extensions, nil

}

// getX509ExtKeyUsage returns []pkix.Extension from []int32
func getX509ExtKeyUsage(x509ExtKeyUsages []int32) ([]pkix.Extension, error) {

	if len(x509ExtKeyUsages) == 0 {
		return extKeyUsageToExtension([]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
	}
	ekuRet := make([]x509.ExtKeyUsage, len(x509ExtKeyUsages))
	for i, eku := range x509ExtKeyUsages {
		// extKeyUsage valid values - https://golang.org/src/crypto/x509/x509.go?s=18153:18173#L621
		if eku < 0 || eku > 13 {
			return nil, fmt.Errorf("invalid x509 ExtKeyUsage value: %d, valid values are [0,1,...13]", eku)
		}
		ekuRet[i] = x509.ExtKeyUsage(eku)
	}
	return extKeyUsageToExtension(ekuRet)
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
