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
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestStatusInterceptor(t *testing.T) {
	t.Parallel()

	table := map[string]struct {
		err      error
		wantCode codes.Code
	}{
		"nil error": {
			err:      nil,
			wantCode: codes.OK,
		},
		"ok": {
			err:      status.Error(codes.OK, "ok error"),
			wantCode: codes.OK,
		},
		"not ok": {
			err:      status.Error(codes.InvalidArgument, "invalid argument"),
			wantCode: codes.InvalidArgument,
		},
		"unknown error": {
			err:      errors.New("unknown error"),
			wantCode: codes.Unknown,
		},
	}

	for name, tt := range table {
		tt := tt
		t.Run(name, func(t *testing.T) {
			handler := func(ctx context.Context, req interface{}) (interface{}, error) {
				return nil, tt.err
			}

			interceptor := StatusInterceptor(func(code codes.Code) {
				if code != tt.wantCode {
					t.Fatalf("got: %v, want: %v", code, tt.wantCode)
				}
			})

			_, err := interceptor(nil, nil, nil, handler)
			if err != nil {
				if tt.err != err {
					t.Errorf("error mismatch, got: %v, want: %v", err, tt.err)
				}
				return
			}
			if tt.err != nil {
				t.Errorf("no error returned, want: %v", tt.err)
			}
		})
	}

}
