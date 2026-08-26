// Copyright 2025 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"
)

// keyTypes lists the values accepted by the -key-type flag. The first alias of
// each entry is the canonical spelling reported back in error messages; the rest
// are the alternate spellings a user is likely to reach for, including the Go
// constant names that crypki's own KeyConfig documentation uses.
var keyTypes = []struct {
	algo    x509.PublicKeyAlgorithm
	aliases []string
}{
	{x509.RSA, []string{"RSA"}},
	{x509.DSA, []string{"DSA"}},
	{x509.ECDSA, []string{"ECDSA"}},
	{x509.Ed25519, []string{"Ed25519"}},
}

// signatureAlgos lists the values accepted by the -signature-algo flag, in the
// same shape as keyTypes. The canonical spellings match x509.SignatureAlgorithm's
// String() output so that a value read off a cert can be fed straight back in.
var signatureAlgos = []struct {
	algo    x509.SignatureAlgorithm
	aliases []string
}{
	{x509.SHA1WithRSA, []string{"SHA1-RSA", "SHA1WithRSA"}},
	{x509.SHA256WithRSA, []string{"SHA256-RSA", "SHA256WithRSA"}},
	{x509.SHA384WithRSA, []string{"SHA384-RSA", "SHA384WithRSA"}},
	{x509.SHA512WithRSA, []string{"SHA512-RSA", "SHA512WithRSA"}},
	{x509.DSAWithSHA1, []string{"DSA-SHA1", "DSAWithSHA1"}},
	{x509.DSAWithSHA256, []string{"DSA-SHA256", "DSAWithSHA256"}},
	{x509.ECDSAWithSHA1, []string{"ECDSA-SHA1", "ECDSAWithSHA1"}},
	{x509.ECDSAWithSHA256, []string{"ECDSA-SHA256", "ECDSAWithSHA256"}},
	{x509.ECDSAWithSHA384, []string{"ECDSA-SHA384", "ECDSAWithSHA384"}},
	{x509.ECDSAWithSHA512, []string{"ECDSA-SHA512", "ECDSAWithSHA512"}},
	{x509.SHA256WithRSAPSS, []string{"SHA256-RSAPSS", "SHA256WithRSAPSS"}},
	{x509.SHA384WithRSAPSS, []string{"SHA384-RSAPSS", "SHA384WithRSAPSS"}},
	{x509.SHA512WithRSAPSS, []string{"SHA512-RSAPSS", "SHA512WithRSAPSS"}},
	{x509.PureEd25519, []string{"Ed25519", "PureEd25519"}},
}

// parseKeyType resolves a -key-type flag value, which may be either an algorithm
// name such as "ECDSA" (matched case-insensitively) or the numeric
// x509.PublicKeyAlgorithm value that the JSON config field carries, such as "3".
func parseKeyType(value string) (x509.PublicKeyAlgorithm, error) {
	if n, err := strconv.Atoi(value); err == nil {
		// The bounds mirror config.Validate so that a value rejected in the
		// config file is not silently accepted from the command line.
		algo := x509.PublicKeyAlgorithm(n)
		if algo < x509.RSA || algo > x509.Ed25519 {
			return 0, newAlgoError("key type", value, keyTypeNames())
		}
		return algo, nil
	}
	for _, kt := range keyTypes {
		if matchesAlias(value, kt.aliases) {
			return kt.algo, nil
		}
	}
	return 0, newAlgoError("key type", value, keyTypeNames())
}

// parseSignatureAlgo resolves a -signature-algo flag value, which may be either
// an algorithm name such as "ECDSA-SHA384" (matched case-insensitively) or the
// numeric x509.SignatureAlgorithm value that the JSON config field carries, such
// as "11".
func parseSignatureAlgo(value string) (x509.SignatureAlgorithm, error) {
	if n, err := strconv.Atoi(value); err == nil {
		algo := x509.SignatureAlgorithm(n)
		if algo < x509.SHA1WithRSA || algo > x509.PureEd25519 {
			return 0, newAlgoError("signature algorithm", value, signatureAlgoNames())
		}
		return algo, nil
	}
	for _, sa := range signatureAlgos {
		if matchesAlias(value, sa.aliases) {
			return sa.algo, nil
		}
	}
	return 0, newAlgoError("signature algorithm", value, signatureAlgoNames())
}

func matchesAlias(value string, aliases []string) bool {
	for _, alias := range aliases {
		if strings.EqualFold(value, alias) {
			return true
		}
	}
	return false
}

// keyTypeNames returns the canonical -key-type spellings, for use in help text
// and error messages.
func keyTypeNames() []string {
	names := make([]string, 0, len(keyTypes))
	for _, kt := range keyTypes {
		names = append(names, kt.aliases[0])
	}
	return names
}

// signatureAlgoNames returns the canonical -signature-algo spellings, for use in
// help text and error messages.
func signatureAlgoNames() []string {
	names := make([]string, 0, len(signatureAlgos))
	for _, sa := range signatureAlgos {
		names = append(names, sa.aliases[0])
	}
	return names
}

func newAlgoError(kind, value string, names []string) error {
	return fmt.Errorf("invalid %s %q, want a numeric x509 value or one of: %s", kind, value, strings.Join(names, ", "))
}
