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
	"github.com/yahoo/crypki/config"
	"github.com/yahoo/crypki/proto"
	"github.com/yahoo/crypki/sshcert"
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

	defer func() {
		log.Printf(`m=%s,st=%d,et=%d,err="%v"`, methodName, statusCode, timeElapsedSince(start), err)
	}()
	defer recoverIfPanicked(methodName)

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

	defer func() {
		log.Printf(`m=%s,st=%d,et=%d,err="%v"`, methodName, statusCode, timeElapsedSince(start), err)
	}()
	defer recoverIfPanicked(methodName)

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

	defer func() {
		kid := ""
		if cert != nil {
			kid = cert.KeyId
		}
		log.Printf(`m=%s,id=%q,principals=%q,st=%d,et=%d,err="%v"`, methodName, kid, request.Principals, statusCode, timeElapsedSince(start), err)
	}()
	defer recoverIfPanicked(methodName)

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

	cert, err = sshcert.DecodeRequest(request, ssh.HostCert)
	if err != nil {
		statusCode = http.StatusBadRequest
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	if !s.KeyUsages[config.SSHHostCertEndpoint][request.KeyMeta.Identifier] {
		statusCode = http.StatusBadRequest
		err = fmt.Errorf("cannot use key %q for %q", request.KeyMeta.Identifier, config.SSHHostCertEndpoint)
		return nil, status.Errorf(codes.InvalidArgument, "Bad request: %v", err)
	}

	data, err := s.SignSSHCert(cert, request.KeyMeta.Identifier)
	if err != nil {
		statusCode = http.StatusInternalServerError
		return nil, status.Error(codes.Internal, "Internal server error")
	}
	return &proto.SSHKey{Key: string(data)}, nil
}
