// Copyright 2022 Yahoo.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package healthcheck implements health check service for crypki.
package healthcheck

import (
	"context"

	"github.com/theparanoids/crypki/api"
	"github.com/theparanoids/crypki/proto"
)

// Service implements proto.HealthCheckServer
type Service struct {
	proto.UnimplementedHealthServer
	SigningService *api.SigningService
	KeyID          string
	// InRotation returns true if the instance is intended to serve traffic, false otherwise.
	InRotation func() bool
}

// Check implements the health check service for crypki.
// Based on InRotation() and GetUserSSHCertificateSigningKey() api, it will report appropriate status.
func (s *Service) Check(ctx context.Context, r *proto.HealthCheckRequest) (*proto.HealthCheckResponse, error) {
	if s.InRotation == nil || !s.InRotation() {
		return &proto.HealthCheckResponse{Status: proto.HealthCheckResponse_NOT_SERVING}, nil
	}
	_, err := s.SigningService.GetUserSSHCertificateSigningKey(ctx, &proto.KeyMeta{Identifier: s.KeyID})
	if err != nil {
		return nil, err
	}
	return &proto.HealthCheckResponse{Status: proto.HealthCheckResponse_SERVING}, nil
}
