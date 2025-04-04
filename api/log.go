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

package api

import (
	"fmt"
	"net/http"
	"runtime"
)

type logFunc func(statusCode int, err error)

// logWithCheckingPanic attemps to recover from a possible panic,
// modifies statusCode and err if there was indeed a panic,
// passes the possibly updated status and err to the logFunc,
// then panics again if there was indeed a panic to
// make UnaryInterceptor in server/server.go return "internal server error" to the client.
func logWithCheckingPanic(f logFunc, statusCode *int, err *error) {
	r := recover()
	if r != nil {
		switch r.(type) {
		// Starting Go 1.21 panic with nil results in run-time panic of type *runtime.PanicNilError
		// Ref - https://tip.golang.org/doc/go1.21 and https://github.com/golang/go/issues/25448
		case *runtime.PanicNilError:
		default:
			*statusCode = http.StatusInternalServerError
			*err = fmt.Errorf("panic: %v", r)
			defer panic(r)
		}
	}
	f(*statusCode, *err)
}
