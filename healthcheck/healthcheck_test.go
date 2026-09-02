// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package healthcheck

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/theparanoids/crypki/api"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/scheduler"
	"golang.org/x/crypto/ssh"
)

const testKeyID = "sshuserid"

// mockCertSign implements crypki.CertSign. Only GetSSHCertSigningKey is
// reachable from Check; the rest are here to satisfy the interface.
type mockCertSign struct {
	err error
}

func (m *mockCertSign) GetSSHCertSigningKey(_ context.Context, _ chan scheduler.Request, _ string) ([]byte, error) {
	if m.err != nil {
		return nil, m.err
	}
	return []byte("ssh signing key"), nil
}

func (m *mockCertSign) SignSSHCert(_ context.Context, _ chan scheduler.Request, _ *ssh.Certificate, _ string, _ proto.Priority) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCertSign) GetX509CACert(_ context.Context, _ chan scheduler.Request, _ string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCertSign) SignX509Cert(_ context.Context, _ chan scheduler.Request, _ *x509.Certificate, _ string, _ proto.Priority) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCertSign) GetBlobSigningPublicKey(_ context.Context, _ chan scheduler.Request, _ string) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (m *mockCertSign) SignBlob(_ context.Context, _ chan scheduler.Request, _ []byte, _ crypto.SignerOpts, _ string, _ proto.Priority) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func signingService(signer *mockCertSign, keyUsages map[string]map[string]bool) *api.SigningService {
	return &api.SigningService{
		CertSign:       signer,
		KeyUsages:      keyUsages,
		RequestTimeout: 10,
	}
}

var testKeyUsages = map[string]map[string]bool{
	config.SSHUserCertEndpoint: {testKeyID: true},
}

func TestCheck(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		service    *Service
		wantStatus proto.HealthCheckResponse_ServingStatus
		wantErr    bool
	}{
		"no InRotation configured reports NOT_SERVING": {
			// A nil InRotation is treated as out of rotation rather than
			// dereferenced, so the signing service is never consulted.
			service: &Service{
				SigningService: signingService(&mockCertSign{}, testKeyUsages),
				KeyID:          testKeyID,
			},
			wantStatus: proto.HealthCheckResponse_NOT_SERVING,
		},
		"out of rotation reports NOT_SERVING": {
			service: &Service{
				SigningService: signingService(&mockCertSign{}, testKeyUsages),
				KeyID:          testKeyID,
				InRotation:     func() bool { return false },
			},
			wantStatus: proto.HealthCheckResponse_NOT_SERVING,
		},
		"in rotation with a reachable signing key reports SERVING": {
			service: &Service{
				SigningService: signingService(&mockCertSign{}, testKeyUsages),
				KeyID:          testKeyID,
				InRotation:     func() bool { return true },
			},
			wantStatus: proto.HealthCheckResponse_SERVING,
		},
		"in rotation with a failing signing key returns an error": {
			service: &Service{
				SigningService: signingService(&mockCertSign{err: errors.New("hsm unavailable")}, testKeyUsages),
				KeyID:          testKeyID,
				InRotation:     func() bool { return true },
			},
			wantErr: true,
		},
		"in rotation with an unknown key returns an error": {
			service: &Service{
				SigningService: signingService(&mockCertSign{}, map[string]map[string]bool{}),
				KeyID:          testKeyID,
				InRotation:     func() bool { return true },
			},
			wantErr: true,
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			resp, err := tt.service.Check(context.Background(), &proto.HealthCheckRequest{})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("Check() returned %v, want an error", resp)
				}
				return
			}
			if err != nil {
				t.Fatalf("Check() returned error: %v", err)
			}
			if resp.Status != tt.wantStatus {
				t.Errorf("Check() status = %v, want %v", resp.Status, tt.wantStatus)
			}
		})
	}
}
