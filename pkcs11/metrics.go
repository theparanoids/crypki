// Copyright 2025 Yahoo Inc.
// Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

package pkcs11

import (
	"context"
	p11 "github.com/miekg/pkcs11"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"time"
)

const (
	scopeName = "github.com/theparanoids/crypki/pkcs11"

	pkcs11LatencyMetricName         = "pkcs11_method_latency_ms"
	signerMetadataLatencyMetricName = "signer_method_latency_ms"
)

var (
	meter               = otel.GetMeterProvider().Meter(scopeName)
	signerLatencyMetric metric.Float64Histogram
)

func init() {
	var err error
	if signerLatencyMetric, err = meter.Float64Histogram(
		signerMetadataLatencyMetricName,
		metric.WithUnit("ms"),
		metric.WithDescription("Measures the latency in ms for each signerMetadata method call")); err != nil {
		otel.Handle(err)
	}
}

func ExportSignerMetadataLatencyMetric(operation string, method string, start time.Time) {
	durationMs := float64(time.Since(start).Microseconds()) / 1000.0
	signerLatencyMetric.Record(context.Background(),
		durationMs,
		metric.WithAttributes(
			attribute.String("signer.operation", operation),
			attribute.String("signer.method", method),
		),
	)
}

// InstrumentedPKCS11Ctx is a wrapper around the PKCS11 context that collects oTel metrics.
type InstrumentedPKCS11Ctx struct {
	PKCS11Ctx
	meter metric.Meter

	methodLatencyMetrics metric.Float64Histogram
}

// NewInstrumentedPKCS11Ctx creates a new InstrumentedPKCS11Ctx.
func NewInstrumentedPKCS11Ctx(inner PKCS11Ctx) *InstrumentedPKCS11Ctx {
	instPKCS11Ctx := &InstrumentedPKCS11Ctx{
		PKCS11Ctx: inner,
	}

	instPKCS11Ctx.meter = meter

	var err error
	if instPKCS11Ctx.methodLatencyMetrics, err = instPKCS11Ctx.meter.Float64Histogram(
		pkcs11LatencyMetricName,
		metric.WithUnit("ms"),
		metric.WithDescription("Measures the latency in ms for each PKCS#11 method call")); err != nil {
		otel.Handle(err)
	}
	return instPKCS11Ctx
}

func (i *InstrumentedPKCS11Ctx) exportLatency(method string, start time.Time) {
	durationMs := float64(time.Since(start).Microseconds()) / 1000.0
	i.methodLatencyMetrics.Record(context.Background(),
		durationMs,
		metric.WithAttributes(
			attribute.String("pkcs11.method", method),
		),
	)
}

func (i *InstrumentedPKCS11Ctx) GetAttributeValue(param1 p11.SessionHandle, param2 p11.ObjectHandle, param3 []*p11.Attribute) (ret1 []*p11.Attribute, ret2 error) {
	start := time.Now()
	ret1, ret2 = i.PKCS11Ctx.GetAttributeValue(param1, param2, param3)
	i.exportLatency("GetAttributeValue", start)
	return
}

func (i *InstrumentedPKCS11Ctx) SignInit(param1 p11.SessionHandle, param2 []*p11.Mechanism, param3 p11.ObjectHandle) (ret1 error) {
	start := time.Now()
	ret1 = i.PKCS11Ctx.SignInit(param1, param2, param3)
	i.exportLatency("SignInit", start)
	return
}

func (i *InstrumentedPKCS11Ctx) Sign(param1 p11.SessionHandle, param2 []byte) (ret1 []byte, ret2 error) {
	start := time.Now()
	ret1, ret2 = i.PKCS11Ctx.Sign(param1, param2)
	i.exportLatency("Sign", start)
	return
}

func (i *InstrumentedPKCS11Ctx) Login(param1 p11.SessionHandle, param2 uint, param3 string) (ret1 error) {
	start := time.Now()
	ret1 = i.PKCS11Ctx.Login(param1, param2, param3)
	i.exportLatency("Login", start)
	return
}

func (i *InstrumentedPKCS11Ctx) GenerateRandom(param1 p11.SessionHandle, param2 int) (ret1 []byte, ret2 error) {
	start := time.Now()
	ret1, ret2 = i.PKCS11Ctx.GenerateRandom(param1, param2)
	i.exportLatency("GenerateRandom", start)
	return
}

func (i *InstrumentedPKCS11Ctx) FindObjectsInit(param1 p11.SessionHandle, param2 []*p11.Attribute) (ret1 error) {
	start := time.Now()
	ret1 = i.PKCS11Ctx.FindObjectsInit(param1, param2)
	i.exportLatency("FindObjectsInit", start)
	return
}

func (i *InstrumentedPKCS11Ctx) FindObjects(param1 p11.SessionHandle, param2 int) (ret1 []p11.ObjectHandle, ret2 bool, ret3 error) {
	start := time.Now()
	ret1, ret2, ret3 = i.PKCS11Ctx.FindObjects(param1, param2)
	i.exportLatency("FindObjects", start)
	return
}

func (i *InstrumentedPKCS11Ctx) FindObjectsFinal(param1 p11.SessionHandle) (ret1 error) {
	start := time.Now()
	ret1 = i.PKCS11Ctx.FindObjectsFinal(param1)
	i.exportLatency("FindObjectsFinal", start)
	return
}

func (i *InstrumentedPKCS11Ctx) CloseSession(param1 p11.SessionHandle) (ret1 error) {
	start := time.Now()
	ret1 = i.PKCS11Ctx.CloseSession(param1)
	i.exportLatency("CloseSession", start)
	return
}

func (i *InstrumentedPKCS11Ctx) OpenSession(param1 uint, param2 uint) (ret1 p11.SessionHandle, ret2 error) {
	start := time.Now()
	ret1, ret2 = i.PKCS11Ctx.OpenSession(param1, param2)
	i.exportLatency("OpenSession", start)
	return
}

func (i *InstrumentedPKCS11Ctx) GetSlotList(param1 bool) (ret1 []uint, ret2 error) {
	start := time.Now()
	ret1, ret2 = i.PKCS11Ctx.GetSlotList(param1)
	i.exportLatency("GetSlotList", start)
	return
}

func (i *InstrumentedPKCS11Ctx) GetSlotInfo(param1 uint) (ret1 p11.SlotInfo, ret2 error) {
	start := time.Now()
	ret1, ret2 = i.PKCS11Ctx.GetSlotInfo(param1)
	i.exportLatency("GetSlotInfo", start)
	return
}

func (i *InstrumentedPKCS11Ctx) GetTokenInfo(param1 uint) (ret1 p11.TokenInfo, ret2 error) {
	start := time.Now()
	ret1, ret2 = i.PKCS11Ctx.GetTokenInfo(param1)
	i.exportLatency("GetTokenInfo", start)
	return
}
