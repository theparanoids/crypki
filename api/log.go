package api

import (
	"fmt"
	"net/http"
)

type logFunc func(statusCode int, err error)

const panicRecoveryPrefix = "panic: "

// logWithCheckingPanic attemps to recover from a possible panic,
// modifies statusCode and err if there was indeed a panic,
// passes the possibly updated status and err to the logFunc,
// then panics again if there was indeed a panic to
// make UnaryInterceptor in server/server.go return "internal server error" to the client.
func logWithCheckingPanic(f logFunc, statusCode int, err error) {
	if r := recover(); r != nil {
		statusCode = http.StatusInternalServerError
		err = fmt.Errorf("%s%v", panicRecoveryPrefix, r)
		defer panic(r)
	}
	f(statusCode, err)
}
