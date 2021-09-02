// Copyright 2021 Yahoo.
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

package interceptor

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StatusInterceptor returns a UnaryServerInterceptor that provides a hook to access the
// grpc status code for each request.
func StatusInterceptor(fn func(code codes.Code)) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)

		// determine status code
		var code codes.Code
		if err != nil {
			if sts, ok := status.FromError(err); !ok {
				code = codes.Unknown
			} else {
				code = sts.Code()
			}
		} else {
			code = codes.OK
		}

		fn(code)
		return resp, err
	}
}
