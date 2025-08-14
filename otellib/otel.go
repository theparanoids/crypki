// Copyright 2024 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package otellib

import (
	"context"
	"crypto/tls"
	"log"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"google.golang.org/grpc/credentials"
)

var nilShutdown = func(ctx context.Context) error { return nil }

// InitOTelSDK initializes the OTel meter provider
func InitOTelSDK(ctx context.Context, collectorEndpoint string, tlsConfig *tls.Config, res *resource.Resource) (shutdown func(context.Context) error) {
	// Set up an OTel exporter for metrics.

	var metricExporter sdkmetric.Exporter
	var err error

	if isGRPCProtocol(collectorEndpoint) {
		// gRPC protocol.
		var opts []otlpmetricgrpc.Option
		opts = append(opts, otlpmetricgrpc.WithEndpoint(trimScheme(collectorEndpoint)))
		opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(tlsConfig)))
		metricExporter, err = otlpmetricgrpc.New(ctx, opts...)
		if err != nil {
			log.Printf("failed to create oTel metric exporter: %v\n", err)
			return nilShutdown
		}
	} else {
		// HTTP protocol.
		var opts []otlpmetrichttp.Option
		opts = append(opts, otlpmetrichttp.WithEndpoint(trimScheme(collectorEndpoint)))
		opts = append(opts, otlpmetrichttp.WithTLSClientConfig(tlsConfig))
		metricExporter, err = otlpmetrichttp.New(ctx, opts...)
		if err != nil {
			log.Printf("failed to create oTel metric http exporter: %v\n", err)
			return nilShutdown
		}
	}

	// Set up a metric provider.
	meterProvider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(metricExporter),
		),
		sdkmetric.WithResource(res),
	)

	otel.SetMeterProvider(meterProvider)

	return meterProvider.Shutdown
}

// isGRPCProtocol checks if the endpoint is using gRPC protocol
// Port 4317 is the default gRPC port for OpenTelemetry.
// Ref: https://opentelemetry.io/docs/specs/otel/protocol/exporter/
func isGRPCProtocol(endpoint string) bool {
	return strings.HasPrefix(endpoint, "grpc") || strings.Contains(endpoint, ":4317")
}

func trimScheme(s string) string {
	separatorIndex := strings.Index(s, "://")
	if separatorIndex != -1 {
		return s[separatorIndex+3:]
	}
	return s
}
