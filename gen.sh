#!/usr/bin/env bash
# Copyright 2021 Yahoo.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#
# This script does 2 things:
# 1. Install all the tool binaries required to generate code.
# 2. Run "go generate" to generate code.
set -euo pipefail

main() {
  # Since different projects may have different versions of tool binaries,
  # we first install tool binaries of the version specified in the go.mod of this project,
  # and the binaries will be placed under the tools_bin directory of this project and git-ignored.
  GOBIN=$(pwd)/tools_bin
  export GOBIN
  go install github.com/golang/mock/mockgen
  go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway
  go install google.golang.org/grpc/cmd/protoc-gen-go-grpc
  go install google.golang.org/protobuf/cmd/protoc-gen-go

  # Make sure that we are using the tool binaries which are just built to generate code.
  export PATH=$GOBIN:$PATH
  go generate ./...
}

main
