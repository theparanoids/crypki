// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	recovery "github.com/grpc-ecosystem/go-grpc-middleware/recovery"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/theparanoids/crypki/api"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/pkcs11"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/server/interceptor"
	"github.com/theparanoids/crypki/server/scheduler"
)

const defaultLogFile = "/var/log/crypki/server.log"

// grpcHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise. More: https://grpc.io/blog/coreos
func grpcHandlerFunc(ctx context.Context, grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r.WithContext(ctx))
		} else {
			otherHandler.ServeHTTP(w, r.WithContext(ctx))
		}
	})
}

// initHTTPServer initializes HTTP server with TLS credentials and returns http.Server.
func initHTTPServer(ctx context.Context, tlsConfig *tls.Config,
	grpcServer *grpc.Server, gwmux *runtime.ServeMux, addr string,
	idleTimeout, readTimeout, writeTimeout uint) *http.Server {
	mux := http.NewServeMux()
	// handler to check if service is up
	mux.HandleFunc("/ruok", func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprintln(w, "imok")
	})
	mux.Handle("/", gwmux)

	srv := &http.Server{
		Addr: addr,
		// to discard noisy messages like
		// "http: TLS handshake error from 1.2.3.4:53651: EOF"
		ErrorLog:     log.New(io.Discard, "", 0),
		Handler:      grpcHandlerFunc(ctx, grpcServer, mux),
		IdleTimeout:  time.Duration(idleTimeout) * time.Second,
		ReadTimeout:  time.Duration(readTimeout) * time.Second,
		WriteTimeout: time.Duration(writeTimeout) * time.Second,
		TLSConfig:    tlsConfig,
	}
	return srv
}

func getIPs() (ips []net.IP, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, errors.New("unable to fetch interfaces: " + err.Error())
	}

	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, errors.New("unable to extract addresses from interface: " + err.Error())
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// Main represents the main function which starts crypki server.
func Main() {
	cfgVal := ""
	logFile := ""
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	flag.StringVar(&cfgVal, "config", "", "Configuration file path")
	flag.StringVar(&logFile, "logfile", defaultLogFile, "Log file path")
	flag.Parse()

	if cfgVal == "" {
		log.Fatalf("no configuration file provided")
	}

	cfg, err := config.Parse(cfgVal)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC | log.Lmicroseconds)
	file, err := os.OpenFile(logFile, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalf("failed to create log file: %v", err)
	}
	log.SetOutput(file)
	go logRotate(file)

	type priorityDispatchInfo struct {
		endpoint        string
		priSchedFeature bool
	}
	keyUsages := make(map[string]map[string]bool)
	maxValidity := make(map[string]uint64)
	requestChan := make(map[string]chan scheduler.Request)
	idEpMap := make(map[string]priorityDispatchInfo)
	endpointMap := make(map[string]bool)

	for _, usage := range cfg.KeyUsages {
		keyUsages[usage.Endpoint] = make(map[string]bool)
		for _, id := range usage.Identifiers {
			idEpMap[id] = priorityDispatchInfo{usage.Endpoint, usage.PrioritySchedulingEnabled}
			keyUsages[usage.Endpoint][id] = true
		}
		requestChan[usage.Endpoint] = make(chan scheduler.Request)
		maxValidity[usage.Endpoint] = usage.MaxValidity
	}

	for _, key := range cfg.Keys {
		// Since we could have multiple identifier for 1 endpoint, we need to ensure we start collecting request per endpoint
		// and not per identifier.
		v := idEpMap[key.Identifier]
		if !endpointMap[v.endpoint] {
			endpointMap[v.endpoint] = true
			p := &scheduler.Pool{Name: v.endpoint, PoolSize: key.SessionPoolSize, FeatureEnabled: v.priSchedFeature}
			go scheduler.CollectRequest(ctx, requestChan[v.endpoint], p)
		}
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal(err)
	}

	ips, err := getIPs()
	if err != nil {
		log.Fatal(err)
	}

	signer, err := pkcs11.NewCertSign(ctx, cfg.ModulePath, cfg.Keys, keyUsages[config.X509CertEndpoint], hostname, ips)
	if err != nil {
		log.Fatalf("unable to initialize cert signer: %v", err)
	}

	// Following TLS config will be used to initialize grpc server and
	// grpc gateway server.
	tlsConfig, err := tlsConfiguration(
		cfg.TLSCACertPath,
		cfg.TLSServerCertPath,
		cfg.TLSServerKeyPath,
		cfg.TLSClientAuthMode)
	if err != nil {
		log.Fatalf("crypki: failed to setup TLS config: %v", err)
	}

	// Setup gRPC gateway
	gwmux := runtime.NewServeMux()

	recoveryHandler := func(p interface{}) (err error) {
		return status.Errorf(codes.Internal, "internal server error")
	}

	var server *http.Server
	var grpcServer *grpc.Server
	interceptors := []grpc.UnaryServerInterceptor{
		recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(recoveryHandler)),
		interceptor.AccessLogInterceptor(),
	}
	if cfg.ShutdownOnInternalFailure {
		criteria := cfg.ShutdownOnInternalFailureCriteria
		shutdownCounterConfig := interceptor.ShutdownCounterConfig{
			ReportOnly:            criteria.ReportMode,
			ConsecutiveCountLimit: int32(criteria.ConsecutiveCountLimit),
			TimeRangeCountLimit:   int32(criteria.TimerCountLimit),
			TickerDuration:        time.Duration(criteria.TimerDurationSecond) * time.Second,
			ShutdownFn: func() {
				grpcServer.GracefulStop()
				if err := server.Shutdown(ctx); err != nil {
					log.Fatalf("failed to shutdown server: %v", err)
				}
			},
		}
		interceptors = append([]grpc.UnaryServerInterceptor{
			interceptor.StatusInterceptor((interceptor.NewShutdownCounter(ctx, shutdownCounterConfig)).InterceptorFn),
		}, interceptors...)
	}

	// Setup gRPC server and http server
	grpcServer = grpc.NewServer([]grpc.ServerOption{
		grpc.Creds(credentials.NewTLS(tlsConfig)),
		grpc.ChainUnaryInterceptor(interceptors...),
	}...)

	ss := &api.SigningService{CertSign: signer, KeyUsages: keyUsages, MaxValidity: maxValidity, RequestChan: requestChan}
	if err := proto.RegisterSigningHandlerServer(ctx, gwmux, ss); err != nil {
		log.Fatalf("crypki: failed to register signing service handler, err: %v", err)
	}

	proto.RegisterSigningServer(grpcServer, ss)

	server = initHTTPServer(ctx, tlsConfig, grpcServer, gwmux, net.JoinHostPort(cfg.TLSHost, cfg.TLSPort),
		cfg.IdleTimeout, cfg.ReadTimeout, cfg.WriteTimeout)
	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("starting server on %s", server.Addr)
	if err := server.Serve(tls.NewListener(listener, server.TLSConfig)); err != nil {
		log.Fatalf("failed to serve: %s", err)
	}

}

// tlsConfiguration returns tls configuration.
func tlsConfiguration(caCertPath string, certPath, keyPath string, clientAuthMode tls.ClientAuthType) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		NextProtos:               []string{"h2", "http/1.1"}, // prefer HTTP/2 explicitly
		PreferServerCipherSuites: true,
		SessionTicketsDisabled:   true, // Don't allow session resumption
	}
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(caCert)

	keypem, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certpem, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	if certpem != nil && keypem != nil {
		mycert, err := tls.X509KeyPair(certpem, keypem)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = make([]tls.Certificate, 1)
		cfg.Certificates[0] = mycert
		cfg.ClientCAs = certPool
		cfg.ClientAuth = clientAuthMode
	}

	// Use only modern ciphers.
	cfg.CipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}

	return cfg, nil
}

// logRotate handles log rotation without process restart.
func logRotate(lf *os.File) {
	var err error
	c := make(chan os.Signal, 1)
	name := lf.Name()
	for {
		signal.Notify(c, syscall.SIGHUP)
		<-c
		log.Println("crypki: received  HUP signal for logrotation")
		lf.Close()
		lf, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
		if err != nil {
			log.Fatalf("crypki: couldn't rotate the log, err=%v", err)
		}
		log.SetOutput(lf)
		log.Printf("crypki: rotated logfile: %s", name)
	}
}
