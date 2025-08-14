// Copyright 2025 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package otellib

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/resource"
	colmetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func Test_trimScheme(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{
			name: "https scheme",
			s:    "https://example.com:1234",
			want: "example.com:1234",
		},
		{
			name: "grpc scheme",
			s:    "grpc://example.com:1234",
			want: "example.com:1234",
		},
		{
			name: "no scheme",
			s:    "example.com:1234",
			want: "example.com:1234",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := trimScheme(tt.s); got != tt.want {
				t.Errorf("trimScheme() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isGRPCProtocol(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     bool
	}{
		{
			name:     "not grpc scheme",
			endpoint: "https://example.com:1234",
			want:     false,
		},
		{
			name:     "grpc scheme",
			endpoint: "grpc://example.com:1234",
			want:     true,
		},
		{
			name:     "4317 port",
			endpoint: "example.com:4317",
			want:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isGRPCProtocol(tt.endpoint); got != tt.want {
				t.Errorf("isGRPCProtocol() = %v, want %v", got, tt.want)
			}
		})
	}
}

func generateCertificate() (*tls.Certificate, *x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2025),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		Subject:      pkix.Name{Organization: []string{"My Server"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  privKey,
	}

	return tlsCert, cert, nil
}

type mockMetricsServer struct {
	colmetricpb.UnimplementedMetricsServiceServer
}

func (m *mockMetricsServer) Export(_ context.Context, _ *colmetricpb.ExportMetricsServiceRequest) (*colmetricpb.ExportMetricsServiceResponse, error) {
	return &colmetricpb.ExportMetricsServiceResponse{}, nil
}

func TestInitOTelSDK(t *testing.T) {
	ctx := context.Background()
	oTelRes := resource.NewWithAttributes("test.schema")

	tlsSvrCert, caCert, err := generateCertificate()
	if err != nil {
		t.Fatalf("Failed to generate TLS certificate: %v", err)
	}
	svrTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsSvrCert},
	}
	crtPool := x509.NewCertPool()
	crtPool.AddCert(caCert)
	clientTLSConfig := &tls.Config{
		RootCAs: crtPool,
	}

	// HTTP endpoint test case.
	t.Run("should initialize with HTTP endpoint", func(t *testing.T) {
		// Create a mock HTTP server that the exporter can connect to
		httpServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK) // Respond with success
		}))
		defer httpServer.Close()

		httpServer.TLS = svrTLSConfig
		httpServer.StartTLS()

		shutdown := InitOTelSDK(ctx, httpServer.URL, clientTLSConfig, oTelRes)

		require.NotNil(t, shutdown, "Shutdown function should not be nil on success")

		err = shutdown(ctx)
		require.NoError(t, err, "Shutdown should not produce an error")
	})

	// gRPC endpoint test case.
	t.Run("should initialize with gRPC endpoint", func(t *testing.T) {
		// Create a listener on a random available port
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(svrTLSConfig)))
		go func() {
			_ = grpcServer.Serve(lis)
		}()
		defer grpcServer.GracefulStop()
		colmetricpb.RegisterMetricsServiceServer(grpcServer, &mockMetricsServer{})

		grpcEndpoint := fmt.Sprintf("grpc://%s", lis.Addr().String())

		shutdown := InitOTelSDK(ctx, grpcEndpoint, clientTLSConfig, oTelRes)

		require.NotNil(t, shutdown)

		err = shutdown(ctx)
		require.NoError(t, err)
	})

	t.Run("should fail with an unreachable endpoint", func(t *testing.T) {
		invalidEndpoint := "localhost:99999"
		shutdown := InitOTelSDK(ctx, invalidEndpoint, &tls.Config{}, oTelRes)

		require.NotNil(t, shutdown, "Function should still return a function on failure")
	})
}
