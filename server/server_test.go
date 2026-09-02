// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc"

	"github.com/theparanoids/crypki/api"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/healthcheck"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/scheduler"
)

const testKeyID = "sshuserid"

// writeKeyPair writes a self-signed certificate and its key into dir and
// returns their paths. The certificate doubles as its own CA, which is all
// tlsServerConfiguration and tlsClientConfiguration need to build a
// tls.Config.
func writeKeyPair(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "crypki-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	write := func(path, blockType string, der []byte) {
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0600); err != nil {
			t.Fatalf("failed to write %s: %v", path, err)
		}
	}
	write(certPath, "CERTIFICATE", der)
	write(keyPath, "EC PRIVATE KEY", keyDER)
	return certPath, keyPath
}

// mockCertSign implements crypki.CertSign. Only GetSSHCertSigningKey is
// reachable from the health check; the rest satisfy the interface.
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

func newHealthCheckService(t *testing.T, inRotation func() bool, signErr error) *healthcheck.Service {
	t.Helper()
	return &healthcheck.Service{
		SigningService: &api.SigningService{
			CertSign: &mockCertSign{err: signErr},
			KeyUsages: map[string]map[string]bool{
				config.SSHUserCertEndpoint: {testKeyID: true},
			},
			RequestTimeout: 10,
		},
		KeyID:      testKeyID,
		InRotation: inRotation,
	}
}

func TestGetIPs(t *testing.T) {
	t.Parallel()

	// Any host running the tests has at least a loopback interface, so the
	// list is expected to be non-empty and to contain only parseable
	// addresses.
	ips, err := getIPs()
	if err != nil {
		t.Fatalf("getIPs() returned error: %v", err)
	}
	if len(ips) == 0 {
		t.Fatal("getIPs() returned no addresses")
	}
	loopback := false
	for _, ip := range ips {
		if ip == nil {
			t.Error("getIPs() returned a nil address")
			continue
		}
		if ip.IsLoopback() {
			loopback = true
		}
	}
	if !loopback {
		t.Error("getIPs() returned no loopback address")
	}
}

func TestStandardCipherSuites(t *testing.T) {
	t.Parallel()

	suites := standardCipherSuites()
	if len(suites) == 0 {
		t.Fatal("standardCipherSuites() returned no suites")
	}

	// Every suite has to be one Go still considers secure, and none may repeat.
	secure := map[uint16]bool{}
	for _, s := range tls.CipherSuites() {
		secure[s.ID] = true
	}
	seen := map[uint16]bool{}
	for _, id := range suites {
		if !secure[id] {
			t.Errorf("cipher suite %#04x is not in tls.CipherSuites()", id)
		}
		if seen[id] {
			t.Errorf("cipher suite %#04x is listed twice", id)
		}
		seen[id] = true
	}
}

func TestGrpcHandlerFunc(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		protoMajor  int
		contentType string
		wantOther   bool
	}{
		"an http/2 grpc request goes to the grpc server": {
			protoMajor:  2,
			contentType: "application/grpc",
			wantOther:   false,
		},
		"an http/2 grpc request with a subtype goes to the grpc server": {
			protoMajor:  2,
			contentType: "application/grpc+proto",
			wantOther:   false,
		},
		"an http/1.1 request goes to the other handler": {
			protoMajor:  1,
			contentType: "application/grpc",
			wantOther:   true,
		},
		"an http/2 request that is not grpc goes to the other handler": {
			protoMajor:  2,
			contentType: "application/json",
			wantOther:   true,
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			grpcServer := grpc.NewServer()
			t.Cleanup(grpcServer.Stop)

			other := make(chan struct{}, 1)
			handler := grpcHandlerFunc(ctx, grpcServer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				other <- struct{}{}
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodPost, "/crypki.Signing/PostUserSSHCertificate", nil)
			req.ProtoMajor = tt.protoMajor
			req.Header.Set("Content-Type", tt.contentType)
			handler.ServeHTTP(httptest.NewRecorder(), req)

			select {
			case <-other:
				if !tt.wantOther {
					t.Error("request was routed to the other handler, want the grpc server")
				}
			default:
				if tt.wantOther {
					t.Error("request was not routed to the other handler")
				}
			}
		})
	}
}

func TestInitHTTPServer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	grpcServer := grpc.NewServer()
	t.Cleanup(grpcServer.Stop)

	gwmux := http.NewServeMux()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	srv := initHTTPServer(ctx, tlsConfig, grpcServer, gwmux, "localhost:4443", 1, 2, 3)

	if srv.Addr != "localhost:4443" {
		t.Errorf("Addr = %q, want %q", srv.Addr, "localhost:4443")
	}
	if srv.TLSConfig != tlsConfig {
		t.Error("TLSConfig was not carried over")
	}
	if srv.IdleTimeout != time.Second || srv.ReadTimeout != 2*time.Second || srv.WriteTimeout != 3*time.Second {
		t.Errorf("timeouts = (%v, %v, %v), want (1s, 2s, 3s)",
			srv.IdleTimeout, srv.ReadTimeout, srv.WriteTimeout)
	}

	// The mux the server is built around answers /ruok itself rather than
	// forwarding it to the gateway.
	rec := httptest.NewRecorder()
	srv.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ruok", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET /ruok status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "imok\n" {
		t.Errorf("GET /ruok body = %q, want %q", rec.Body.String(), "imok\n")
	}
}

func TestHcHandlerServeHTTP(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		method     string
		path       string
		inRotation func() bool
		signErr    error
		wantStatus int
		wantBody   string
	}{
		"GET /ruok while in rotation is ok": {
			method:     http.MethodGet,
			path:       "/ruok",
			inRotation: func() bool { return true },
			wantStatus: http.StatusOK,
			wantBody:   "imok\n",
		},
		"GET /status while in rotation is ok": {
			method:     http.MethodGet,
			path:       "/status",
			inRotation: func() bool { return true },
			wantStatus: http.StatusOK,
			wantBody:   "imok\n",
		},
		"an unknown path is rejected": {
			method:     http.MethodGet,
			path:       "/healthz",
			inRotation: func() bool { return true },
			wantStatus: http.StatusBadRequest,
		},
		"a non-GET method is rejected": {
			method:     http.MethodPost,
			path:       "/ruok",
			inRotation: func() bool { return true },
			wantStatus: http.StatusBadRequest,
		},
		"being out of rotation is reported as an error": {
			method:     http.MethodGet,
			path:       "/ruok",
			inRotation: func() bool { return false },
			wantStatus: http.StatusBadRequest,
		},
		"a failing health check is reported as an error": {
			method:     http.MethodGet,
			path:       "/ruok",
			inRotation: func() bool { return true },
			signErr:    errors.New("hsm unavailable"),
			wantStatus: http.StatusBadRequest,
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			handler := &hcHandler{hcService: newHealthCheckService(t, tt.inRotation, tt.signErr)}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestStatusCheckHandlerServeHTTP(t *testing.T) {
	t.Parallel()

	existing := filepath.Join(t.TempDir(), "status.html")
	if err := os.WriteFile(existing, []byte("OK\n"), 0600); err != nil {
		t.Fatal(err)
	}

	testcases := map[string]struct {
		method     string
		path       string
		statusFile string
		wantStatus int
	}{
		"GET /status.html with the file present is ok": {
			method:     http.MethodGet,
			path:       "/status.html",
			statusFile: existing,
			wantStatus: http.StatusOK,
		},
		"GET /status.html with the file missing is a 404": {
			method:     http.MethodGet,
			path:       "/status.html",
			statusFile: filepath.Join(t.TempDir(), "absent.html"),
			wantStatus: http.StatusNotFound,
		},
		"another path is a 404": {
			method:     http.MethodGet,
			path:       "/ruok",
			statusFile: existing,
			wantStatus: http.StatusNotFound,
		},
		"a non-GET method is a 404": {
			method:     http.MethodPost,
			path:       "/status.html",
			statusFile: existing,
			wantStatus: http.StatusNotFound,
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			handler := &statusCheckHandler{statusFilePath: tt.statusFile}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, tt.path, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestTLSServerConfiguration(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeKeyPair(t, t.TempDir())
	absent := filepath.Join(t.TempDir(), "absent.pem")

	t.Run("a readable key pair produces a server config", func(t *testing.T) {
		t.Parallel()
		cfg, err := tlsServerConfiguration(certPath, certPath, keyPath, tls.RequireAndVerifyClientCert)
		if err != nil {
			t.Fatalf("tlsServerConfiguration() returned error: %v", err)
		}
		if cfg.MinVersion != tls.VersionTLS12 {
			t.Errorf("MinVersion = %#04x, want %#04x", cfg.MinVersion, tls.VersionTLS12)
		}
		if len(cfg.Certificates) != 1 {
			t.Fatalf("Certificates has %d entries, want 1", len(cfg.Certificates))
		}
		if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
			t.Errorf("ClientAuth = %v, want %v", cfg.ClientAuth, tls.RequireAndVerifyClientCert)
		}
		if cfg.ClientCAs == nil {
			t.Error("ClientCAs was not populated")
		}
		if !cfg.SessionTicketsDisabled {
			t.Error("SessionTicketsDisabled = false, want true")
		}
		if len(cfg.CipherSuites) != len(standardCipherSuites()) {
			t.Errorf("CipherSuites has %d entries, want %d", len(cfg.CipherSuites), len(standardCipherSuites()))
		}
	})

	missing := map[string]struct{ caPath, certPath, keyPath string }{
		"a missing CA cert is an error":     {absent, certPath, keyPath},
		"a missing server cert is an error": {certPath, absent, keyPath},
		"a missing key is an error":         {certPath, certPath, absent},
	}
	for label, tt := range missing {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			if cfg, err := tlsServerConfiguration(tt.caPath, tt.certPath, tt.keyPath, tls.NoClientCert); err == nil {
				t.Fatalf("tlsServerConfiguration() = %v, want an error", cfg)
			}
		})
	}

	t.Run("a key that does not match the cert is an error", func(t *testing.T) {
		t.Parallel()
		_, otherKeyPath := writeKeyPair(t, t.TempDir())
		if cfg, err := tlsServerConfiguration(certPath, certPath, otherKeyPath, tls.NoClientCert); err == nil {
			t.Fatalf("tlsServerConfiguration() = %v, want an error", cfg)
		}
	})
}

func TestTLSClientConfiguration(t *testing.T) {
	t.Parallel()

	certPath, keyPath := writeKeyPair(t, t.TempDir())
	absent := filepath.Join(t.TempDir(), "absent.pem")

	t.Run("a readable key pair produces a client config", func(t *testing.T) {
		t.Parallel()
		cfg, err := tlsClientConfiguration(certPath, certPath, keyPath)
		if err != nil {
			t.Fatalf("tlsClientConfiguration() returned error: %v", err)
		}
		if cfg.InsecureSkipVerify {
			t.Error("InsecureSkipVerify = true, want false")
		}
		if cfg.RootCAs == nil {
			t.Error("RootCAs was not populated")
		}
		if cfg.GetClientCertificate == nil {
			t.Fatal("GetClientCertificate was not set")
		}
		// The callback is backed by a cert reloader that has already loaded
		// the pair once, so it hands back a certificate straight away.
		cert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
		if err != nil {
			t.Fatalf("GetClientCertificate() returned error: %v", err)
		}
		if cert == nil || len(cert.Certificate) == 0 {
			t.Error("GetClientCertificate() returned no certificate")
		}
	})

	missing := map[string]struct{ caPath, certPath, keyPath string }{
		"a missing CA cert is an error":     {absent, certPath, keyPath},
		"a missing client cert is an error": {certPath, absent, keyPath},
		"a missing key is an error":         {certPath, certPath, absent},
	}
	for label, tt := range missing {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			if cfg, err := tlsClientConfiguration(tt.caPath, tt.certPath, tt.keyPath); err == nil {
				t.Fatalf("tlsClientConfiguration() = %v, want an error", cfg)
			}
		})
	}

	t.Run("a CA file that is not a certificate is an error", func(t *testing.T) {
		t.Parallel()
		notACert := filepath.Join(t.TempDir(), "notacert.pem")
		if err := os.WriteFile(notACert, []byte("not a certificate\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if cfg, err := tlsClientConfiguration(notACert, certPath, keyPath); err == nil {
			t.Fatalf("tlsClientConfiguration() = %v, want an error", cfg)
		}
	})
}
