// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package proto

import (
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
)

// Custom forwarder that returns 201 http status for successful POST request.
func forwardCheckoutResp(ctx context.Context, mux *runtime.ServeMux, marshaler runtime.Marshaler, w http.ResponseWriter, req *http.Request, resp proto.Message, opts ...func(context.Context, http.ResponseWriter, proto.Message) error) {
	if req.Method == http.MethodPost && resp != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
	}
	runtime.ForwardResponseMessage(ctx, mux, marshaler, w, req, resp, opts...)
}

func init() {
	forward_Signing_PostX509Certificate_0 = forwardCheckoutResp
	forward_Signing_PostUserSSHCertificate_0 = forwardCheckoutResp
	forward_Signing_PostHostSSHCertificate_0 = forwardCheckoutResp
}
