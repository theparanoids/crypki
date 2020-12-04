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

// GetUserSSHCertificateAvailableSigningKeys returns all available keys that can sign user SSH certificates.
func (s *SigningService) GetUserSSHCertificateAvailableSigningKeys(ctx context.Context, e *empty.Empty) (*proto.KeyMetas, error) {
	const methodName = "GetUserSSHCertificateAvailableSigningKeys"
	statusCode := http.StatusOK
	start := time.Now()
	var err error

	f := func(statusCode int, err error) {
		log.Printf(`m=%s,st=%d,et=%d,err="%v"`, methodName, statusCode, timeElapsedSince(start), err)
	}
	defer logWithCheckingPanic(f, &statusCode, &err)

	var keys []*proto.KeyMeta
	for id := range s.KeyUsages[config.SSHUserCertEndpoint] {
		keys = append(keys, &proto.KeyMeta{Identifier: id})
	}
	return &proto.KeyMetas{Keys: keys}, nil
}

// GetUserSSHCertificateSigningKey returns the public signing key of the
// specified key that signs the user ssh certificate.
func (s *SigningService) GetUserSSHCertificateSigningKey(ctx context.Context, keyMeta *proto.KeyMeta) (*proto.SSHKey, error) {
	const methodName = "GetUserSSHCertificateSigningKey"
	statusCode := http.StatusOK
	start := time.Now()
	var err error

	f := func(statusCode int, err error) {
		log.Printf(`m=%s,st=%d,et=%d,err="%v"`, methodName, statusCode, timeElapsedSince(start), err)
	}
	defer logWithCheckingPanic(f, &statusCode, &err)

	if keyMeta == nil {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("keyMeta is empty for %q", config.SSHUserCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	// if client cancelled the request or request timed out, we should skip processing
	select {
	case <-ctx.Done():
		statusCode = http.StatusServiceUnavailable
		err = fmt.Errorf("%s for request %q for %q", ctx.Err(), keyMeta.Identifier, config.SSHUserCertEndpoint)
		return nil, status.Errorf(codes.Canceled, "Bad request: %v", err)
	default:
	}

	if !s.KeyUsages[config.SSHUserCertEndpoint][keyMeta.Identifier] {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("cannot use key %q for %q", keyMeta.Identifier, config.SSHUserCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	key, err := s.GetSSHCertSigningKey(keyMeta.Identifier)
	if err != nil {
		statusCode = http.StatusInternalServerError
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	return &proto.SSHKey{Key: string(key)}, nil
}

// PostUserSSHCertificate signs the SSH user certificate given request fields using the specified key.
func (s *SigningService) PostUserSSHCertificate(ctx context.Context, request *proto.SSHCertificateSigningRequest) (*proto.SSHKey, error) {
	const methodName = "PostUserSSHCertificate"
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
		err = fmt.Errorf("request.keyMeta is empty for %q", config.SSHUserCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	// if client cancelled the request or request timed out, we should skip processing
	select {
	case <-ctx.Done():
		statusCode = http.StatusServiceUnavailable
		err = fmt.Errorf("%s for request %q for %q", ctx.Err(), request.KeyMeta.Identifier, config.SSHUserCertEndpoint)
		return nil, status.Errorf(codes.Canceled, "Bad request: %v", err)
	default:
	}

	maxValidity := s.MaxValidity[config.SSHUserCertEndpoint]
	if err := checkValidity(request.GetValidity(), maxValidity); err != nil {
		statusCode = http.StatusBadRequest
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	cert, err = sshcert.DecodeRequest(request, ssh.UserCert, s.KeyIDProcessor)
	if err != nil {
		statusCode = http.StatusBadRequest
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	if !s.KeyUsages[config.SSHUserCertEndpoint][request.KeyMeta.Identifier] {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("cannot use key %q for %q", request.KeyMeta.Identifier, config.SSHUserCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	data, err := s.SignSSHCert(cert, request.KeyMeta.Identifier)
	if err != nil {
		statusCode = http.StatusInternalServerError
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	return &proto.SSHKey{Key: string(data)}, nil
}
