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
		name  string
		input interface{}
		want  string // See logStr below for the format
	}{
		{
			name:  "panic with string",
			input: "string",
			want:  "st: 500, err: panic: string",
		},
		{
			name:  "panic with error",
			input: errors.New("error"),
			want:  "st: 500, err: panic: error",
		},
		{
			name:  "no panic",
			input: nil,
			want:  "st: 200, err: <nil>", // See inputStatusCode below for 200
		},
	}
	const (
		logStr          = "st: %d, err: %v"
		inputStatusCode = http.StatusOK
	)
	var inputError error

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
			defer logWithCheckingPanic(f, inputStatusCode, inputError)
			panic(tc.input)
		})
	}
}
