// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/theparanoids/crypki/config"
	"github.com/theparanoids/crypki/proto"
	"github.com/theparanoids/crypki/sshcert"
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetHostSSHCertificateAvailableSigningKeys returns all available keys that can sign host SSH certificates.
func (s *SigningService) GetHostSSHCertificateAvailableSigningKeys(ctx context.Context, e *empty.Empty) (*proto.KeyMetas, error) {
	const methodName = "GetHostSSHCertificateAvailableSigningKeys"
	statusCode := http.StatusOK
	start := time.Now()
	var err error

	f := func(statusCode int, err error) {
		log.Printf(`m=%s,st=%d,et=%d,err="%v"`, methodName, statusCode, timeElapsedSince(start), err)
	}
	defer logWithCheckingPanic(f, &statusCode, &err)

	var keys []*proto.KeyMeta
	for id := range s.KeyUsages[config.SSHHostCertEndpoint] {
		keys = append(keys, &proto.KeyMeta{Identifier: id})
	}
	return &proto.KeyMetas{Keys: keys}, nil
}

// GetHostSSHCertificateSigningKey returns the public signing key of the
// specified key that signs the host ssh certificate.
func (s *SigningService) GetHostSSHCertificateSigningKey(ctx context.Context, keyMeta *proto.KeyMeta) (*proto.SSHKey, error) {
	const methodName = "GetHostSSHCertificateSigningKey"
	statusCode := http.StatusOK
	start := time.Now()
	var err error

	f := func(statusCode int, err error) {
		log.Printf(`m=%s,st=%d,et=%d,err="%v"`, methodName, statusCode, timeElapsedSince(start), err)
	}
	defer logWithCheckingPanic(f, &statusCode, &err)

	if keyMeta == nil {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("keyMeta is empty for %q", config.SSHHostCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	if !s.KeyUsages[config.SSHHostCertEndpoint][keyMeta.Identifier] {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("cannot use key %q for %q", keyMeta.Identifier, config.SSHHostCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	// ctx can have an error only when client cancels or request has timed out.
	if err := ctx.Err(); err != nil {
		statusCode = http.StatusServiceUnavailable
		err = fmt.Errorf("%s for request for %q", ctx.Err(), config.SSHHostCertEndpoint)
		return nil, status.Errorf(codes.Canceled, "Abandoning request: %v", err)
	}

	key, err := s.GetSSHCertSigningKey(keyMeta.Identifier)
	if err != nil {
		statusCode = http.StatusInternalServerError
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	return &proto.SSHKey{Key: string(key)}, nil
}

// PostHostSSHCertificate signs the SSH host certificate given request fields using the specified key.
func (s *SigningService) PostHostSSHCertificate(ctx context.Context, request *proto.SSHCertificateSigningRequest) (*proto.SSHKey, error) {
	const methodName = "PostHostSSHCertificate"
	statusCode := http.StatusCreated
	start := time.Now()
	var err error
	var cert *ssh.Certificate

	f := func(statusCode int, err error) {
		kid := ""
		if cert != nil {
			kid = cert.KeyId
		}
		log.Printf(`m=%s,id=%q,principals=%q,st=%d,et=%d,err="%v"`,
			methodName, kid, request.Principals, statusCode, timeElapsedSince(start), err)
	}
	defer logWithCheckingPanic(f, &statusCode, &err)

	if request.KeyMeta == nil {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("request.keyMeta is empty for %q", config.SSHHostCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	maxValidity := s.MaxValidity[config.SSHHostCertEndpoint]
	if err := checkValidity(request.GetValidity(), maxValidity); err != nil {
		statusCode = http.StatusBadRequest
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	cert, err = sshcert.DecodeRequest(request, ssh.HostCert, s.KeyIDProcessor)
	if err != nil {
		statusCode = http.StatusBadRequest
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	if !s.KeyUsages[config.SSHHostCertEndpoint][request.KeyMeta.Identifier] {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("cannot use key %q for %q", request.KeyMeta.Identifier, config.SSHHostCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	// If client disconnects or has timed out, we do not need to process the request.
	// https://grpc.io/blog/deadlines/#checking-deadlines
	if err := ctx.Err(); err != nil {
		statusCode = http.StatusServiceUnavailable
		err = fmt.Errorf("%s for request %q", ctx.Err(), config.SSHHostCertEndpoint)
		return nil, status.Errorf(codes.Canceled, "Cancel request: %v", err)
	}

	data, err := s.SignSSHCert(cert, request.KeyMeta.Identifier)
	if err != nil {
		statusCode = http.StatusInternalServerError
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	return &proto.SSHKey{Key: string(data)}, nil
}
