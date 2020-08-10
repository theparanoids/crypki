package server

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
