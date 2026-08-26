// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/theparanoids/crypki"
	"github.com/theparanoids/crypki/config"
)

// TestKeyConfigFromCAConfig guards the CA cert configuration file -> KeyConfig
// copy. A field missed here is neither a compile error nor a failure anywhere
// else, it just quietly generates a CA that does not match the file the
// operator wrote, so assert on every field rather than a chosen few.
func TestKeyConfigFromCAConfig(t *testing.T) {
	t.Parallel()

	cc := &crypki.CAConfig{
		Country:            "US",
		State:              "CA",
		Locality:           "Sunnyvale",
		Organization:       "Foo Org",
		OrganizationalUnit: "Foo Org Unit",
		CommonName:         "foo.example.com",
		ValidityPeriod:     1234,
		Identifier:         "x509-key",
		KeyLabel:           "host_x509",
		KeyType:            int(x509.ECDSA),
		SignatureAlgo:      int(x509.ECDSAWithSHA384),
		SlotNumber:         7,
		UserPinPath:        "/path/pin",
		SubjectKeyId:       crypki.SubjectKeyIdSHA256,
	}
	want := config.KeyConfig{
		Country:                "US",
		State:                  "CA",
		Locality:               "Sunnyvale",
		Organization:           "Foo Org",
		OrganizationalUnit:     "Foo Org Unit",
		CommonName:             "foo.example.com",
		ValidityPeriod:         1234,
		Identifier:             "x509-key",
		KeyLabel:               "host_x509",
		KeyType:                x509.ECDSA,
		SignatureAlgo:          x509.ECDSAWithSHA384,
		SlotNumber:             7,
		UserPinPath:            "/path/pin",
		SubjectKeyId:           crypki.SubjectKeyIdSHA256,
		X509CACertLocation:     "/tmp/ca.pem",
		CreateCACertIfNotExist: true,
		SessionPoolSize:        2,
	}
	if got := keyConfigFromCAConfig(cc, "/tmp/ca.pem"); !reflect.DeepEqual(got, want) {
		t.Errorf("keyConfigFromCAConfig() = %+v, want %+v", got, want)
	}
}
