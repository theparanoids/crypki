// Copyright 2025 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package main

import (
	"crypto/x509"
	"testing"

	"github.com/theparanoids/crypki"
)

func TestParseKeyType(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		want    x509.PublicKeyAlgorithm
		wantErr bool
	}{
		{"name", "ECDSA", x509.ECDSA, false},
		{"name is case insensitive", "ecdsa", x509.ECDSA, false},
		{"name rsa", "RSA", x509.RSA, false},
		{"name ed25519", "ed25519", x509.Ed25519, false},
		{"numeric matches the json config field", "3", x509.ECDSA, false},
		{"numeric rsa", "1", x509.RSA, false},
		{"numeric zero is unknown", "0", 0, true},
		{"numeric above range", "5", 0, true},
		{"numeric negative", "-1", 0, true},
		{"unknown name", "P256", 0, true},
		{"empty", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseKeyType(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseKeyType(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("parseKeyType(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestParseSignatureAlgo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		value   string
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{"canonical name", "ECDSA-SHA384", x509.ECDSAWithSHA384, false},
		{"go constant name", "ECDSAWithSHA384", x509.ECDSAWithSHA384, false},
		{"name is case insensitive", "ecdsa-sha384", x509.ECDSAWithSHA384, false},
		{"rsa name", "SHA256-RSA", x509.SHA256WithRSA, false},
		{"rsa pss name", "SHA512-RSAPSS", x509.SHA512WithRSAPSS, false},
		{"ed25519 name", "Ed25519", x509.PureEd25519, false},
		{"numeric matches the json config field", "11", x509.ECDSAWithSHA384, false},
		{"numeric rsa", "4", x509.SHA256WithRSA, false},
		{"numeric below range rejects deprecated md5", "2", 0, true},
		{"numeric zero is unknown", "0", 0, true},
		{"numeric above range", "17", 0, true},
		{"unknown name", "SHA3-256", 0, true},
		{"empty", "", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSignatureAlgo(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseSignatureAlgo(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("parseSignatureAlgo(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// TestCanonicalNamesRoundTrip guards the canonical spellings against drift from
// crypto/x509, so a value copied out of a parsed cert stays a valid flag value.
func TestCanonicalNamesRoundTrip(t *testing.T) {
	t.Parallel()
	for _, kt := range keyTypes {
		if got := kt.algo.String(); got != kt.aliases[0] {
			t.Errorf("key type %d canonical name = %q, x509 String() = %q", kt.algo, kt.aliases[0], got)
		}
	}
	for _, sa := range signatureAlgos {
		if got := sa.algo.String(); got != sa.aliases[0] {
			t.Errorf("signature algo %d canonical name = %q, x509 String() = %q", sa.algo, sa.aliases[0], got)
		}
	}
}

func TestApplyKeyOverrides(t *testing.T) {
	t.Parallel()
	base := func() *crypki.CAConfig {
		return &crypki.CAConfig{
			Identifier:    "x509-key",
			KeyLabel:      "host_x509",
			KeyType:       int(x509.RSA),
			SignatureAlgo: int(x509.SHA256WithRSA),
		}
	}

	t.Run("empty overrides leave the config untouched", func(t *testing.T) {
		t.Parallel()
		cc := base()
		if err := applyKeyOverrides(cc, "", "", "", ""); err != nil {
			t.Fatalf("applyKeyOverrides() error = %v", err)
		}
		if *cc != *base() {
			t.Errorf("applyKeyOverrides() modified the config: got %+v, want %+v", cc, base())
		}
	})

	t.Run("overrides take precedence over the config", func(t *testing.T) {
		t.Parallel()
		cc := base()
		if err := applyKeyOverrides(cc, "x509-key-ec", "host_x509_ec", "ECDSA", "ECDSA-SHA384"); err != nil {
			t.Fatalf("applyKeyOverrides() error = %v", err)
		}
		want := &crypki.CAConfig{
			Identifier:    "x509-key-ec",
			KeyLabel:      "host_x509_ec",
			KeyType:       int(x509.ECDSA),
			SignatureAlgo: int(x509.ECDSAWithSHA384),
		}
		if *cc != *want {
			t.Errorf("applyKeyOverrides() = %+v, want %+v", cc, want)
		}
	})

	t.Run("partial override only touches the field given", func(t *testing.T) {
		t.Parallel()
		cc := base()
		if err := applyKeyOverrides(cc, "", "", "", "11"); err != nil {
			t.Fatalf("applyKeyOverrides() error = %v", err)
		}
		want := base()
		want.SignatureAlgo = int(x509.ECDSAWithSHA384)
		if *cc != *want {
			t.Errorf("applyKeyOverrides() = %+v, want %+v", cc, want)
		}
	})

	t.Run("bad key type is reported and the config is not partially applied", func(t *testing.T) {
		t.Parallel()
		cc := base()
		if err := applyKeyOverrides(cc, "", "", "P256", ""); err == nil {
			t.Fatal("applyKeyOverrides() expected an error for an unknown key type")
		}
		if cc.KeyType != int(x509.RSA) {
			t.Errorf("KeyType = %d, want %d left untouched", cc.KeyType, x509.RSA)
		}
	})

	t.Run("bad signature algo is reported", func(t *testing.T) {
		t.Parallel()
		cc := base()
		if err := applyKeyOverrides(cc, "", "", "", "SHA3-256"); err == nil {
			t.Fatal("applyKeyOverrides() expected an error for an unknown signature algorithm")
		}
		if cc.SignatureAlgo != int(x509.SHA256WithRSA) {
			t.Errorf("SignatureAlgo = %d, want %d left untouched", cc.SignatureAlgo, x509.SHA256WithRSA)
		}
	})
}
