// Copyright 2026 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package otellib

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPMiddleware(t *testing.T) {
	t.Parallel()

	handler := NewHTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), "test-operation")

	srv := httptest.NewServer(handler)
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL + "/x509/cert")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatalf("failed to drain body: %v", err)
	}
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusTeapot)
	}
}

func TestHTTPMiddlewareServeHTTP(t *testing.T) {
	t.Parallel()

	testcases := map[string]struct {
		next       http.Handler
		target     string
		wantStatus int
		wantBody   string
	}{
		"request is passed through to the next handler": {
			next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("imok\n"))
			}),
			target:     "/ruok",
			wantStatus: http.StatusOK,
			wantBody:   "imok\n",
		},
		"a panic in the next handler becomes a 500": {
			next: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				panic("handler exploded")
			}),
			target:     "/sig/x509-cert/keys/x509-key",
			wantStatus: http.StatusInternalServerError,
		},
	}

	for label, tt := range testcases {
		tt := tt
		t.Run(label, func(t *testing.T) {
			t.Parallel()
			// newHTTPMiddleware is exercised directly rather than through
			// NewHTTPMiddleware so that the recover path is reached without
			// otelhttp's own handling in the way.
			middleware := newHTTPMiddleware(tt.next)
			if middleware.panicCounter == nil {
				t.Fatal("newHTTPMiddleware left panicCounter nil")
			}

			rec := httptest.NewRecorder()
			middleware.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tt.target, nil))

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && rec.Body.String() != tt.wantBody {
				t.Errorf("body = %q, want %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}
