// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

// Package proto contains proto generated code.
package proto

// use protoc 3.19.2
//go:generate protoc -I. -I../third_party/googleapis --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. sign.proto healthcheck.proto
//go:generate protoc -I. -I../third_party/googleapis --grpc-gateway_out=paths=source_relative:. --grpc-gateway_opt logtostderr=true --grpc-gateway_opt paths=source_relative --grpc-gateway_opt generate_unbound_methods=true sign.proto
//go:generate mockgen -source=./sign_grpc.pb.go -destination=./sign_grpc_mock.go -package=proto
