package api

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestLogWithCheckingPanic(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name       string
		statusCode int
		err        error
		panic      interface{}
		want       string // See logStr below for the format
	}{
		{
			name:       "panic with string",
			statusCode: http.StatusOK,
			err:        nil,
			panic:      "string",
			want:       "st: 500, err: panic: string",
		},
		{
			name:       "panic with error",
			statusCode: http.StatusOK,
			err:        nil,
			panic:      errors.New("error"),
			want:       "st: 500, err: panic: error",
		},
		{
			name:       "no panic",
			statusCode: http.StatusOK,
			err:        nil,
			panic:      nil,
			want:       "st: 200, err: <nil>", // See inputStatusCode below for 200
		},
		{
			name:       "no panic with error",
			statusCode: http.StatusBadRequest,
			err:        errors.New("bad request"),
			panic:      nil,
			want:       "st: 400, err: bad request",
		},
	}
	const logStr = "st: %d, err: %v"

	for _, tc := range testCases {
		// https://github.com/golang/go/wiki/CommonMistakes#using-goroutines-on-loop-iterator-variables
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := ""
			f := func(statusCode int, err error) {
				got = fmt.Sprintf(logStr, statusCode, err)
			}

			defer func() {
				// Capture the panic thrown from logWithCheckingPanic.
				recover()
				if got != tc.want {
					t.Errorf("got: %q, want: %q", got, tc.want)
				}
			}()
			var statusCode int
			var err error
			defer logWithCheckingPanic(f, &statusCode, &err)
			statusCode = tc.statusCode
			err = tc.err
			panic(tc.panic)
		})
	}
}
