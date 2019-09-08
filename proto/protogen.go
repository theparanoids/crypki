// Copyright 2019, Oath Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

// Package proto contains proto generated code.
package proto

//go:generate protoc -I. -I$GOPATH/src -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --go_out=plugins=grpc:. sign.proto
//go:generate protoc -I. -I$GOPATH/src -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis --grpc-gateway_out=logtostderr=true:./ sign.proto
// use protoc 3.9.1

// run the following command after generating proto files to generate mock
//go:generate $GOPATH/bin/mockgen -source=./sign.pb.go -destination=./mock/mock.go -package=mock

// run the following commands to install the gomock
// go get github.com/golang/mock/gomock
// go install github.com/golang/mock/mockgen
