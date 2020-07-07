package api

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
)

type logTestCase struct {
	name string
	panicInput interface{}
}

func TestLogWithCheckingPanic(t *testing.T) {
	t.Parallel()
	testCases := []*logTestCase{
		{
			name: "panic with string",
			panicInput: "string",
		},
		{
			name: "panic with error",
			panicInput: errors.New("error"),
		},
		{
			name: "no panic",
			panicInput: nil,
		},
	}
	
	for _, tc := range testCases {
		testLogWithCheckingPanic(t, tc)
	}
}

func testLogWithCheckingPanic(t *testing.T, tc *logTestCase) {
	const (
		logStr = "st: %d, err: %v"
		inputStatusCode = http.StatusOK
	)
	var inputError error

	want := fmt.Sprintf(logStr, http.StatusInternalServerError, "panic: " + fmt.Sprintf("%s", tc.panicInput))
	if tc.panicInput == nil {
		want = fmt.Sprintf(logStr, inputStatusCode, inputError)
	}

	// Make the channel buffered to avoid deadlock.
	logC := make(chan string, 1)
	f := func(statusCode int, err error) {
		logC <- fmt.Sprintf(logStr, statusCode, err)
	}

	defer func() {
		// Capture the panic thrown from logWithCheckingPanic.
		recover()
		got := <-logC
		if get != want {
			t.Errorf("%s failed, got: %s, want: %s", tc.name, got, want)
		}
	}()
	defer logWithCheckingPanic(f, inputStatusCode, inputError)
	panic(tc.panicInput)
}