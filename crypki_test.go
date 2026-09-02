// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package crypki

import "testing"

func TestCAConfigLoadDefaults(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		in   CAConfig
		want CAConfig
	}{
		"empty config gets every default": {
			in: CAConfig{},
			want: CAConfig{
				Country:            defaultCounty,
				Organization:       defaultCompany,
				OrganizationalUnit: defaultOrganization,
				CommonName:         defaultCommonName,
				ValidityPeriod:     defaultValidityPeriod,
				SubjectKeyId:       SubjectKeyIdSHA1,
			},
		},
		"populated config is left alone": {
			in: CAConfig{
				Country:            "US",
				Organization:       "Yahoo Inc.",
				OrganizationalUnit: "Paranoids",
				CommonName:         "ca.example.com",
				ValidityPeriod:     3600,
				SubjectKeyId:       SubjectKeyIdSHA256,
			},
			want: CAConfig{
				Country:            "US",
				Organization:       "Yahoo Inc.",
				OrganizationalUnit: "Paranoids",
				CommonName:         "ca.example.com",
				ValidityPeriod:     3600,
				SubjectKeyId:       SubjectKeyIdSHA256,
			},
		},
		"fields not defaulted stay empty": {
			// State and Locality have no default, and the PKCS#11 fields are
			// the caller's to fill in.
			in: CAConfig{Country: "US", State: "", Identifier: "x509-key"},
			want: CAConfig{
				Country:            "US",
				Organization:       defaultCompany,
				OrganizationalUnit: defaultOrganization,
				CommonName:         defaultCommonName,
				ValidityPeriod:     defaultValidityPeriod,
				SubjectKeyId:       SubjectKeyIdSHA1,
				Identifier:         "x509-key",
			},
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			got := tt.in
			got.LoadDefaults()
			if got != tt.want {
				t.Errorf("LoadDefaults() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestKeyIDProcess(t *testing.T) {
	t.Parallel()

	// The default KeyID adds no metadata, so Process is expected to be the
	// identity function. A replacement KeyIDProcessor is where the metadata
	// goes; this only pins the behaviour crypki ships with.
	var p KeyIDProcessor = &KeyID{}
	for _, kid := range []string{"", "prins=Bob, crTime=20200529T010015"} {
		got, err := p.Process(kid)
		if err != nil {
			t.Fatalf("Process(%q) returned error: %v", kid, err)
		}
		if got != kid {
			t.Errorf("Process(%q) = %q, want %q", kid, got, kid)
		}
	}
}
