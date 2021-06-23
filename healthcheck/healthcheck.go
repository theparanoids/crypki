// Package healthcheck implements health check service for crypki.
package healthcheck

import (
	"context"

	"github.com/theparanoids/crypki/api"
	"github.com/theparanoids/crypki/proto"
)

// HealthCheckService implements proto.HealthCheckServer
type HealthCheckService struct {
	proto.UnimplementedHealthServer
	SigningService *api.SigningService
	KeyID          string
	// InRotation returns true if the instance is intended to serve traffic, false otherwise.
	InRotation func() bool
}

// Check implements the health check service for crypki.
// Based on InRotation() and GetUserSSHCertificateSigningKey() api, it will report appropriate status.
func (h *HealthCheckService) Check(ctx context.Context, r *proto.HealthCheckRequest) (*proto.HealthCheckResponse, error) {
	if h.InRotation == nil || !h.InRotation() {
		return &proto.HealthCheckResponse{Status: proto.HealthCheckResponse_NOT_SERVING}, nil
	}
	_, err := h.SigningService.GetUserSSHCertificateSigningKey(ctx, &proto.KeyMeta{Identifier: h.KeyID})
	if err != nil {
		return nil, err
	}
	return &proto.HealthCheckResponse{Status: proto.HealthCheckResponse_SERVING}, nil
}
