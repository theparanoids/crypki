package otellib

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	semconv "go.opentelemetry.io/otel/semconv/v1.20.0"
)

const scopeName = "github.com/theparanoids/crypki/otellib"

const handlerPanic = "http.handler.panic"

type httpMiddleware struct {
	next  http.Handler
	meter metric.Meter

	panicCounter metric.Int64Counter
}

// NewHTTPMiddleware wraps an http.Handler with OpenTelemetry instrumentation.
func NewHTTPMiddleware(handler http.Handler, operation string) http.Handler {
	h := newHTTPMiddleware(handler)
	return otelhttp.NewHandler(h, operation)
}

func newHTTPMiddleware(nextHandler http.Handler) *httpMiddleware {
	middleware := &httpMiddleware{
		next: nextHandler,
	}
	middleware.meter = otel.GetMeterProvider().Meter(scopeName)

	var err error
	if middleware.panicCounter, err = middleware.meter.Int64Counter(
		handlerPanic,
		metric.WithUnit("1"),
		metric.WithDescription("Count the number of HTTP handler panic"),
	); err != nil {
		otel.Handle(err)
	}

	return middleware
}

// ServeHTTP implements http.Handler.
func (h *httpMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// A labeler is always available in the request context by otelhttp package.
	labeler, _ := otelhttp.LabelerFromContext(r.Context())
	// Add the http.target attribute to the OTel labeler.
	if r.URL != nil {
		labeler.Add(semconv.HTTPTargetKey.String(r.URL.RequestURI()))
	}
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf(`panic captured, %v, %v`, string(debug.Stack()), rec)

			ctx := r.Context()
			labels := append(labeler.Get(), []attribute.KeyValue{
				attribute.String("http.method", r.Method),
				attribute.String("panic.message", fmt.Sprintf("%v", rec)),
			}...)
			h.panicCounter.Add(ctx, 1, metric.WithAttributes(labels...))
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
	}()
	h.next.ServeHTTP(w, r)
}
