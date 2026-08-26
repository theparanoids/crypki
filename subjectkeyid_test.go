// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package crypki

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseSubjectKeyId(t *testing.T) {
	t.Parallel()
	lit := []byte{0x68, 0x02, 0xec, 0xa0, 0xa6, 0x2b, 0x9c, 0x80, 0x53, 0xb8,
		0x07, 0xf3, 0xca, 0xef, 0xe6, 0x83, 0xbc, 0x2f, 0x13, 0x6e}

	tests := map[string]struct {
		spec        string
		wantHash    string
		wantLiteral []byte
		wantErr     string
	}{
		"empty defaults to sha1":       {"", SubjectKeyIdHashSHA1, nil, ""},
		"blank defaults to sha1":       {"   ", SubjectKeyIdHashSHA1, nil, ""},
		"hash sha1":                    {"hash:sha1", SubjectKeyIdHashSHA1, nil, ""},
		"hash sha1 uppercase":          {"HASH:SHA1", SubjectKeyIdHashSHA1, nil, ""},
		"hash sha1 mixed case":         {"Hash:Sha1", SubjectKeyIdHashSHA1, nil, ""},
		"hash sha1 padded":             {"  hash : sha1  ", SubjectKeyIdHashSHA1, nil, ""},
		"hash sha256":                  {"hash:sha256", SubjectKeyIdHashSHA256, nil, ""},
		"named constant sha1":          {SubjectKeyIdSHA1, SubjectKeyIdHashSHA1, nil, ""},
		"named constant sha256":        {SubjectKeyIdSHA256, SubjectKeyIdHashSHA256, nil, ""},
		"hex plain":                    {"hex:6802eca0a62b9c8053b807f3caefe683bc2f136e", "", lit, ""},
		"hex uppercase":                {"hex:6802ECA0A62B9C8053B807F3CAEFE683BC2F136E", "", lit, ""},
		"hex with colons":              {"hex:68:02:EC:A0:A6:2B:9C:80:53:B8:07:F3:CA:EF:E6:83:BC:2F:13:6E", "", lit, ""},
		"hex with spaces":              {"hex:68 02 ec a0 a6 2b 9c 80 53 b8 07 f3 ca ef e6 83 bc 2f 13 6e", "", lit, ""},
		"hex with dashes":              {"hex:6802-eca0-a62b-9c80-53b8-07f3-caef-e683-bc2f-136e", "", lit, ""},
		"hex with unicode space":       {"hex:6802 eca0", "", []byte{0x68, 0x02, 0xec, 0xa0}, ""},
		"hex shorter than 20 bytes":    {"hex:0a0b0c", "", []byte{0x0a, 0x0b, 0x0c}, ""},
		"text":                         {"text:athenz-ca-2026", "", []byte("athenz-ca-2026"), ""},
		"text keeps inner colons":      {"text:foo:bar:baz", "", []byte("foo:bar:baz"), ""},
		"text keeps surrounding space": {"text:  padded  ", "", []byte("  padded  "), ""},
		"text keeps case":              {"text:MixedCase", "", []byte("MixedCase"), ""},
		"text utf8":                    {"text:测试-ca", "", []byte("测试-ca"), ""},
		"no scheme":                    {"sha1", "", nil, "missing a scheme"},
		"no scheme bare hex":           {"6802eca0", "", nil, "missing a scheme"},
		"unknown scheme":               {"md5:abcd", "", nil, "unknown scheme"},
		"empty scheme":                 {":abcd", "", nil, "unknown scheme"},
		"unknown hash":                 {"hash:md5", "", nil, "unknown hash"},
		"empty hash":                   {"hash:", "", nil, "unknown hash"},
		"hex empty":                    {"hex:", "", nil, "empty literal"},
		"hex only separators":          {"hex: :-: ", "", nil, "empty literal"},
		"hex not hex":                  {"hex:zzzz", "", nil, "not valid hex"},
		"hex odd length":               {"hex:abc", "", nil, "not valid hex"},
		"text empty":                   {"text:", "", nil, "empty literal"},
	}

	for name, tt := range tests {
		name, tt := name, tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseSubjectKeyId(tt.spec)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("ParseSubjectKeyId(%q) = %+v, want an error mentioning %q", tt.spec, got, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("ParseSubjectKeyId(%q) error = %v, want it to mention %q", tt.spec, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseSubjectKeyId(%q) error = %v", tt.spec, err)
			}
			if got.Hash != tt.wantHash {
				t.Errorf("ParseSubjectKeyId(%q).Hash = %q, want %q", tt.spec, got.Hash, tt.wantHash)
			}
			if !bytes.Equal(got.Literal, tt.wantLiteral) {
				t.Errorf("ParseSubjectKeyId(%q).Literal = %x, want %x", tt.spec, got.Literal, tt.wantLiteral)
			}
			if (got.Hash == "") == (got.Literal == nil) {
				t.Errorf("ParseSubjectKeyId(%q) = %+v, want exactly one of Hash and Literal set", tt.spec, got)
			}
		})
	}
}
