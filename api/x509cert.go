// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package api

import (
	"context"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/x509cert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// GetX509CertificateAvailableSigningKeys returns all available keys that can sign X509 certificates.
func (s *SigningService) GetX509CertificateAvailableSigningKeys(ctx context.Context, e *emptypb.Empty) (*proto.KeyMetas, error) {
	const methodName = "GetX509CertificateAvailableSigningKeys"
	statusCode := http.StatusOK
	start := time.Now()
	var err error

	f := func(statusCode int, err error) {
		log.Printf(`m=%s,st=%d,et=%d,err="%v"`, methodName, statusCode, timeElapsedSince(start), err)
	}
	defer logWithCheckingPanic(f, &statusCode, &err)

	var keys []*proto.KeyMeta
	for id := range s.KeyUsages[config.X509CertEndpoint] {
		keys = append(keys, &proto.KeyMeta{Identifier: id})
	}
	return &proto.KeyMetas{Keys: keys}, nil
}

// GetX509CACertificate returns the CA X509 certificate self-signed by the specified key.
func (s *SigningService) GetX509CACertificate(ctx context.Context, keyMeta *proto.KeyMeta) (*proto.X509Certificate, error) {
	const methodName = "GetX509CACertificate"
	statusCode := http.StatusOK
	start := time.Now()
	var err error

	f := func(statusCode int, err error) {
		log.Printf(`m=%s,st=%d,et=%d,err="%v"`, methodName, statusCode, timeElapsedSince(start), err)
	}
	defer logWithCheckingPanic(f, &statusCode, &err)

	if keyMeta == nil {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("keyMeta is empty for %q", config.X509CertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	// ctx can have an error only when client cancels or request has timed out.
	if err := ctx.Err(); err != nil {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("%s for request %q", ctx.Err(), config.X509CertEndpoint)
		return nil, status.Errorf(codes.Canceled, "Bad request: %v", err)
	}

	if !s.KeyUsages[config.X509CertEndpoint][keyMeta.Identifier] {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("cannot use key %q for %q", keyMeta.Identifier, config.X509CertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	cert, err := s.GetX509CACert(ctx, keyMeta.Identifier)
	if err != nil {
		statusCode = http.StatusInternalServerError
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	return &proto.X509Certificate{Cert: string(cert)}, nil
}

// PostX509Certificate signs the given CSR using the specified key and returns a PEM encoded X509 certificate.
func (s *SigningService) PostX509Certificate(ctx context.Context, request *proto.X509CertificateSigningRequest) (*proto.X509Certificate, error) {
	const methodName = "PostX509Certificate"
	statusCode := http.StatusCreated
	start := time.Now()
	subject := pkix.Name{}
	var err error

	f := func(statusCode int, err error) {
		log.Printf(`m=%s,sub=%q,st=%d,et=%d,err="%v"`, methodName, subject, statusCode, timeElapsedSince(start), err)
	}
	defer logWithCheckingPanic(f, &statusCode, &err)

	if request.KeyMeta == nil {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("request.keyMeta is empty for %q", config.X509CertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	var reqCtx context.Context
	var cancel context.CancelFunc
	// create child context with timeout remaining from client request if present else until canceled
	if elapsed, ok := ctx.Deadline(); ok {
		// The request has a timeout, so create a context that is
		// canceled automatically when the timeout expires.
		reqCtx, cancel = context.WithTimeout(ctx, time.Until(elapsed))
	} else {
		reqCtx, cancel = context.WithTimeout(ctx, config.DefaultRequestTimeout)
	}
	defer cancel() // Cancel ctx as soon as PostX509Certificate returns

	maxValidity := s.MaxValidity[config.X509CertEndpoint]
	if err := checkValidity(request.GetValidity(), maxValidity); err != nil {
		statusCode = http.StatusBadRequest
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	req, err := x509cert.DecodeRequest(request)
	if err != nil {
		statusCode = http.StatusBadRequest
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}
	subject = req.Subject

	if !s.KeyUsages[config.X509CertEndpoint][request.KeyMeta.Identifier] {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("cannot use key %q for %q", request.KeyMeta.Identifier, config.X509CertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	type resp struct {
		data []byte
		err  error
	}
	respCh := make(chan resp)
	go func() {
		data, err := s.SignX509Cert(reqCtx, req, request.KeyMeta.Identifier)
		respCh <- resp{data, err}
	}()

	select {
	case <-reqCtx.Done():
		statusCode = http.StatusServiceUnavailable
		switch reqCtx.Err() {
		case context.DeadlineExceeded:
			err = fmt.Errorf("request timed out for %q", config.X509CertEndpoint)
			return nil, status.Errorf(codes.DeadlineExceeded, "%v", err)
		case context.Canceled:
			err = fmt.Errorf("client cancelled request for %q", config.X509CertEndpoint)
		}
		return nil, status.Errorf(codes.Canceled, "%v", err)
	case response := <-respCh:
		if response.err != nil {
			statusCode = http.StatusInternalServerError
			return nil, status.Error(codes.Internal, "Internal server error")
		}
		return &proto.X509Certificate{Cert: string(response.data)}, nil
	}
}
