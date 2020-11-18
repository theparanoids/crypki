// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

// Package proto contains proto generated code.
package proto

//go:generate protoc -I. -I../third_party/googleapis --go_out=. --go-grpc_out=. sign.proto
//go:generate protoc -I. -I../third_party/googleapis --grpc-gateway_out=. --grpc-gateway_opt logtostderr=true --grpc-gateway_opt paths=source_relative --grpc-gateway_opt generate_unbound_methods=true sign.proto
// use protoc 3.13.0

// run the following command after generating proto files to generate mock
//go:generate $GOPATH/bin/mockgen -source=./sign_grpc.pb.go -destination=./mock/mock.go -package=mock

// run the following commands to install the gomock
// go get github.com/golang/mock/gomock
// go install github.com/golang/mock/mockgen
