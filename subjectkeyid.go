// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package crypki

import (
	"encoding/hex"
	"fmt"
	"strings"
	"unicode"
)

// SubjectKeyIdSpec is a parsed CAConfig.SubjectKeyId. Exactly one of its fields
// is set: Hash names a digest to derive the identifier from the CA public key,
// and Literal holds an identifier that was given outright.
type SubjectKeyIdSpec struct {
	Hash    string
	Literal []byte
}

// ParseSubjectKeyId resolves the "scheme:value" form of CAConfig.SubjectKeyId
// as far as it can be resolved without the CA public key, so that a malformed
// value is rejected when the configuration is read rather than at the moment a
// CA certificate has to be issued. An empty spec means SubjectKeyIdSHA1.
func ParseSubjectKeyId(spec string) (SubjectKeyIdSpec, error) {
	if strings.TrimSpace(spec) == "" {
		spec = SubjectKeyIdSHA1
	}
	scheme, value, found := strings.Cut(spec, ":")
	if !found {
		return SubjectKeyIdSpec{}, fmt.Errorf("SubjectKeyId %q is missing a scheme, want %q, %q or %q",
			spec, SubjectKeyIdSchemeHash+":", SubjectKeyIdSchemeHex+":", SubjectKeyIdSchemeText+":")
	}

	switch strings.ToLower(strings.TrimSpace(scheme)) {
	case SubjectKeyIdSchemeHash:
		hash := strings.ToLower(strings.TrimSpace(value))
		switch hash {
		case SubjectKeyIdHashSHA1, SubjectKeyIdHashSHA256:
			return SubjectKeyIdSpec{Hash: hash}, nil
		default:
			return SubjectKeyIdSpec{}, fmt.Errorf("SubjectKeyId %q names an unknown hash %q, want %q or %q",
				spec, hash, SubjectKeyIdHashSHA1, SubjectKeyIdHashSHA256)
		}
	case SubjectKeyIdSchemeHex:
		id, err := decodeHexKeyId(value, spec)
		if err != nil {
			return SubjectKeyIdSpec{}, err
		}
		return SubjectKeyIdSpec{Literal: id}, nil
	case SubjectKeyIdSchemeText:
		// Used exactly as written: trimming or folding here would silently
		// change the identifier a deployment asked for.
		if value == "" {
			return SubjectKeyIdSpec{}, fmt.Errorf("SubjectKeyId %q has an empty literal", spec)
		}
		return SubjectKeyIdSpec{Literal: []byte(value)}, nil
	default:
		return SubjectKeyIdSpec{}, fmt.Errorf("SubjectKeyId %q has an unknown scheme %q, want %q, %q or %q",
			spec, scheme, SubjectKeyIdSchemeHash, SubjectKeyIdSchemeHex, SubjectKeyIdSchemeText)
	}
}

// decodeHexKeyId decodes a literal identifier written as hex digits, ignoring
// the ':' and '-' separators certificate tooling prints between them along with
// any whitespace.
func decodeHexKeyId(value, spec string) ([]byte, error) {
	digits := strings.Map(func(r rune) rune {
		if r == ':' || r == '-' || unicode.IsSpace(r) {
			return -1
		}
		return r
	}, value)
	if digits == "" {
		return nil, fmt.Errorf("SubjectKeyId %q has an empty literal", spec)
	}
	id, err := hex.DecodeString(digits)
	if err != nil {
		return nil, fmt.Errorf("SubjectKeyId %q is not valid hex: %v", spec, err)
	}
	return id, nil
}
