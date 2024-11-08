// Copyright 2024 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package certreload

import (
	"crypto/tls"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMemCertReloader_Reload(t *testing.T) {
	t.Parallel()
	type expect struct {
		cert    *tls.Certificate
		wantErr assert.ErrorAssertionFunc
	}

	tests := []struct {
		name     string
		setup    func(t *testing.T, certPath, keyPath string) (*MemCertReloader, *expect)
		certPath string
		keyPath  string
		wantCert *tls.Certificate
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "happy path",
			certPath: "testdata/client.crt",
			keyPath:  "testdata/client.key",
			setup: func(t *testing.T, certPath, keyPath string) (*MemCertReloader, *expect) {
				certPEM, err := os.ReadFile(certPath)
				if err != nil {
					t.Fatal(err)
				}
				keyPEM, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}

				reloader, err := NewCertReloader(
					CertReloadConfig{
						CertKeyGetter: func() ([]byte, []byte, error) {
							return certPEM, keyPEM, nil
						},
					},
				)
				if err != nil {
					t.Fatal(err)
				}
				wantCrt, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					t.Fatal(err)
				}
				want := &expect{
					cert:    &wantCrt,
					wantErr: assert.NoError,
				}
				return reloader, want
			},
		},
		{
			name:     "getter error",
			certPath: "testdata/invalid.crt",
			keyPath:  "testdata/invalid.key",
			setup: func(t *testing.T, certPath, keyPath string) (*MemCertReloader, *expect) {
				reloader := &MemCertReloader{
					getter: func() ([]byte, []byte, error) {
						return nil, nil, fmt.Errorf("get error")
					},
				}
				want := &expect{
					wantErr: assert.Error,
				}
				return reloader, want
			},
		},
		{
			name:     "unchanged cert",
			certPath: "testdata/client.crt",
			keyPath:  "testdata/client.key",
			setup: func(t *testing.T, certPath, keyPath string) (*MemCertReloader, *expect) {
				certPEM, err := os.ReadFile(certPath)
				if err != nil {
					t.Fatal(err)
				}
				keyPEM, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}

				reloader, err := NewCertReloader(
					CertReloadConfig{
						CertKeyGetter: func() ([]byte, []byte, error) {
							return certPEM, keyPEM, nil
						},
					},
				)
				if err != nil {
					t.Fatal(err)
				}
				wantCert, err := tls.X509KeyPair(certPEM, keyPEM)
				if err != nil {
					t.Fatal(err)
				}
				reloader.cert = &wantCert
				want := &expect{
					cert:    &wantCert,
					wantErr: assert.NoError,
				}
				return reloader, want
			},
		},
		{
			name:     "invalid key pair",
			certPath: "testdata/ca.crt",
			keyPath:  "testdata/client.key",
			setup: func(t *testing.T, certPath, keyPath string) (*MemCertReloader, *expect) {
				certPEM, err := os.ReadFile(certPath)
				if err != nil {
					t.Fatal(err)
				}
				keyPEM, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}
				reloader := &MemCertReloader{
					getter: func() ([]byte, []byte, error) {
						return certPEM, keyPEM, nil
					},
				}
				if err != nil {
					t.Fatal(err)
				}
				want := &expect{
					wantErr: assert.Error,
				}
				return reloader, want
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reloader, want := tt.setup(t, tt.certPath, tt.keyPath)
			gotErr := reloader.Reload()
			if !want.wantErr(t, gotErr, "unexpected error") {
				return
			}
			assert.Equal(t, reloader.cert, want.cert, "unexpected result")
		})
	}
}
