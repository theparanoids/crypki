package interceptor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	grpc_testing "github.com/grpc-ecosystem/go-grpc-middleware/testing"
	pb_testproto "github.com/grpc-ecosystem/go-grpc-middleware/testing/testproto"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

const (
	caCName     = "ca-example"
	serverCName = "server-example"
	clientCName = "client-example"
)

type fakeTimer struct {
	t time.Time
}

func (f *fakeTimer) reset() {
	f.t = time.Unix(1234567890, 987654321)
}

func (f *fakeTimer) now() time.Time {
	now := f.t
	f.t = f.t.Add(time.Millisecond * 1234)
	return now
}

func signX509Cert(unsignedCert, caCert *x509.Certificate, pubKey *rsa.PublicKey,
	caPrivKey *rsa.PrivateKey) (*x509.Certificate, []byte, error) {
	certBytes, err := x509.CreateCertificate(rand.Reader, unsignedCert, caCert, pubKey, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	b := pem.Block{Type: "CERTIFICATE", Bytes: certBytes}
	pem := pem.EncodeToMemory(&b)

	return cert, pem, nil
}

func genSelfSignedCAX509Cert() (*x509.Certificate, []byte, *rsa.PrivateKey, error) {
	var unsignedCert = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:    []string{"US"},
			CommonName: caCName,
		},
		DNSNames:              []string{caCName},
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, pem, err := signX509Cert(unsignedCert, unsignedCert, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, pem, priv, nil
}

func genAndSignX509Cert(cname string, caCert *x509.Certificate, caKey *rsa.PrivateKey) ([]byte, []byte, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	privPem := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	var unsignedCert = &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:    []string{"US"},
			CommonName: cname,
		},
		DNSNames:  []string{cname},
		NotBefore: time.Now().Add(-10 * time.Second),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageCRLSign,
		IsCA: false,
	}

	_, certPem, err := signX509Cert(unsignedCert, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return nil, nil, err
	}
	return certPem, privPem, nil
}

func TestAccessLogInterceptor(t *testing.T) {
	// Create ping request for testing.
	ping := &pb_testproto.PingRequest{Value: "something", SleepTimeMs: 9999}

	// Create CA credentials for mTLS.
	ca, _, caPriv, err := genSelfSignedCAX509Cert()
	if err != nil {
		t.Fatalf("failed to gerenate self signed ca cert, err: %v", err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AddCert(ca)

	tests := []struct {
		name        string
		init        func()
		setupServer func(ctx context.Context, t *testing.T, listener *bufconn.Listener) (*grpc.Server, func())
		setupClient func(ctx context.Context, svr *grpc.Server, listener *bufconn.Listener) pb_testproto.TestServiceClient
		wantLog     string
	}{
		{
			name: "happy path",
			setupServer: func(ctx context.Context, t *testing.T, listener *bufconn.Listener) (*grpc.Server, func()) {
				svrCertPem, svrPrivPem, err := genAndSignX509Cert(serverCName, ca, caPriv)
				if err != nil {
					t.Fatalf("failed to gerenate server cert, err: %v", err)
				}

				svrCertificate, err := tls.X509KeyPair(svrCertPem, svrPrivPem)
				if err != nil {
					t.Fatalf("failed to load x509 key pair, err: %v", err)
				}

				svrTLSConfig := &tls.Config{
					ClientAuth:   tls.RequireAndVerifyClientCert,
					Certificates: []tls.Certificate{svrCertificate},
					ClientCAs:    caCertPool,
				}

				timer := &fakeTimer{}
				interceptor := &accessLogInterceptor{
					timeNow: timer.now,
				}

				grpcServer := grpc.NewServer([]grpc.ServerOption{
					grpc.Creds(credentials.NewTLS(svrTLSConfig)),
					grpc.UnaryInterceptor(interceptor.Func),
				}...)

				testService := &grpc_testing.TestPingService{T: t}
				pb_testproto.RegisterTestServiceServer(grpcServer, testService)

				go func() {
					if err := grpcServer.Serve(listener); err != nil {
						panic(err)
					}
				}()

				closer := func() {
					listener.Close()
					grpcServer.Stop()
				}

				return grpcServer, closer
			},
			setupClient: func(ctx context.Context, server *grpc.Server, listener *bufconn.Listener) pb_testproto.TestServiceClient {
				clientCertPem, clientPrivPem, err := genAndSignX509Cert(clientCName, ca, caPriv)
				if err != nil {
					t.Fatalf("failed to gerenate server cert, err: %v", err)
				}

				clientCertificate, err := tls.X509KeyPair(clientCertPem, clientPrivPem)
				if err != nil {
					t.Fatalf("failed to load x509 key pair, err: %v", err)
				}

				clientTLConfig := &tls.Config{
					Certificates: []tls.Certificate{clientCertificate},
					RootCAs:      caCertPool,
					ServerName:   serverCName,
				}

				clientConn, _ := grpc.DialContext(ctx, "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return listener.Dial()
				}), grpc.WithTransportCredentials(credentials.NewTLS(clientTLConfig)))
				return pb_testproto.NewTestServiceClient(clientConn)
			},
			wantLog: "m=grpcAccessLog,prin=client-example,sts=-6795364578.871346,mtd=Ping,st=0,dur=1234",
		},
		{
			name: "unknown tls info",
			setupServer: func(ctx context.Context, t *testing.T, listener *bufconn.Listener) (*grpc.Server, func()) {
				timer := &fakeTimer{}
				interceptor := &accessLogInterceptor{
					timeNow: timer.now,
				}

				grpcServer := grpc.NewServer([]grpc.ServerOption{
					grpc.UnaryInterceptor(interceptor.Func),
				}...)

				testService := &grpc_testing.TestPingService{T: t}
				pb_testproto.RegisterTestServiceServer(grpcServer, testService)

				go func() {
					if err := grpcServer.Serve(listener); err != nil {
						panic(err)
					}
				}()

				closer := func() {
					listener.Close()
					grpcServer.Stop()
				}

				return grpcServer, closer
			},
			setupClient: func(ctx context.Context, server *grpc.Server, listener *bufconn.Listener) pb_testproto.TestServiceClient {
				clientConn, _ := grpc.DialContext(ctx, "", grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return listener.Dial()
				}), grpc.WithInsecure())
				return pb_testproto.NewTestServiceClient(clientConn)
			},
			wantLog: "m=grpcAccessLog,prin=unknown tls info,sts=-6795364578.871346,mtd=Ping,st=0,dur=1234",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buffer := new(bytes.Buffer)
			log.SetOutput(buffer)
			defer log.SetOutput(os.Stderr)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			listener := bufconn.Listen(1024 * 1024)
			grpcServer, cleanup := tt.setupServer(ctx, t, listener)
			defer cleanup()
			client := tt.setupClient(ctx, grpcServer, listener)
			_, err := client.Ping(ctx, ping)
			if err != nil {
				require.NoError(t, err, "no error should occur.")
			}
			actualLog := string(buffer.Bytes())

			if !strings.Contains(actualLog, tt.wantLog) {
				t.Fatalf("got: %v but want: %v", actualLog, tt.wantLog)
			}
		})
	}
}
