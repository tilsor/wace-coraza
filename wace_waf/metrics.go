package waceWAF

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// meterScope is the instrumentation scope name of the WACE WAF metrics.
const meterScope = "waceWAF"

// attrPhase is the attribute key of the Coraza phase, from 1 to 4.
const attrPhase = "phase"

// durationBuckets are the bucket boundaries, in seconds, of the duration
// histograms: from 100µs to 10s, as in the WACE core.
var durationBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
	0.1, 0.25, 0.5, 1, 2.5, 5, 10,
}

// wafMetrics holds the instruments of WACE WAF. They are created once with
// the meter provider, never on the request path.
type wafMetrics struct {
	exceptionsDuration        metric.Float64Histogram
	requestBodyReadDuration   metric.Float64Histogram
	responseBodyWriteDuration metric.Float64Histogram
	crsDuration               metric.Float64Histogram
	integrationDuration       metric.Float64Histogram
	txDuration                metric.Float64Histogram
	txProcessed               metric.Int64Counter
	txBlocked                 metric.Int64Counter
}

// newWafMetrics creates the WACE WAF instruments with a meter of mp.
func newWafMetrics(mp metric.MeterProvider) (*wafMetrics, error) {
	meter := mp.Meter(meterScope)
	var m wafMetrics
	var err, errs error

	duration := func(name, description string) metric.Float64Histogram {
		h, err := meter.Float64Histogram(name,
			metric.WithDescription(description),
			metric.WithUnit("s"),
			metric.WithExplicitBucketBoundaries(durationBuckets...))
		errs = errors.Join(errs, err)
		return h
	}
	m.exceptionsDuration = duration("wace.waf.exceptions.duration",
		"Time from the start of a phase until its exceptions are evaluated and the active models known.")
	m.requestBodyReadDuration = duration("wace.waf.request.body.read.duration",
		"Time spent reading the request body.")
	m.responseBodyWriteDuration = duration("wace.waf.response.body.write.duration",
		"Time spent writing a chunk of the response body.")
	m.crsDuration = duration("wace.waf.crs.duration",
		"Time spent by Coraza processing a transaction.")
	m.integrationDuration = duration("wace.waf.integration.duration",
		"Time spent by WACE WAF processing a transaction, Coraza included.")
	m.txDuration = duration("wace.waf.transaction.duration",
		"Time from the creation of a transaction until it is logged.")

	m.txProcessed, err = meter.Int64Counter("wace.waf.transaction.processed",
		metric.WithDescription("Transactions logged, by response status code."),
		metric.WithUnit("{transaction}"))
	errs = errors.Join(errs, err)

	m.txBlocked, err = meter.Int64Counter("wace.waf.transaction.blocked",
		metric.WithDescription("Transactions blocked by the WACE decision, by phase."),
		metric.WithUnit("{transaction}"))
	errs = errors.Join(errs, err)

	if errs != nil {
		return nil, errs
	}
	return &m, nil
}

// recordExceptions records the time from start until the exceptions of phase
// were evaluated.
func (m *wafMetrics) recordExceptions(ctx context.Context, phase int, start time.Time) {
	m.exceptionsDuration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attribute.Int(attrPhase, phase)))
}

// recordBlocked records a transaction blocked by the WACE decision in phase.
func (m *wafMetrics) recordBlocked(ctx context.Context, phase int) {
	m.txBlocked.Add(ctx, 1, metric.WithAttributes(attribute.Int(attrPhase, phase)))
}

// metricsState holds the meter provider passed to the WACE core, the
// instruments WACE WAF records with, and the function that flushes and
// releases the provider. They are stored together so they are always
// replaced at once.
type metricsState struct {
	provider    metric.MeterProvider
	instruments *wafMetrics
	shutdown    func(context.Context) error
}

// currentMetrics holds the current metrics state. It is replaced by NewWAF
// when otel_url changes, while transactions may be recording on it.
var currentMetrics atomic.Pointer[metricsState]

// getMetrics returns the current WACE WAF instruments.
func getMetrics() *wafMetrics {
	return currentMetrics.Load().instruments
}

func init() {
	currentMetrics.Store(newNoopMetrics())
}

var serviceName = semconv.ServiceNameKey.String("waceWAF-service")

// newNoopMetrics returns a metrics state that records nothing.
func newNoopMetrics() *metricsState {
	mp := noop.NewMeterProvider()
	// noop instruments never fail
	instruments, _ := newWafMetrics(mp)
	return &metricsState{
		provider:    mp,
		instruments: instruments,
		shutdown:    func(context.Context) error { return nil },
	}
}

// newMetrics returns a metrics state that exports to the OpenTelemetry
// Collector at url through OTLP over gRPC, or one that records nothing if
// url is empty.
func newMetrics(ctx context.Context, url string) (*metricsState, error) {
	if url == "" {
		return newNoopMetrics(), nil
	}

	res, err := resource.New(ctx, resource.WithAttributes(serviceName))
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics resource: %w", err)
	}

	// Note the use of insecure transport here. TLS is recommended in production.
	exporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(url),
		otlpmetricgrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create metrics exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(2*time.Second))),
		sdkmetric.WithResource(res),
	)
	instruments, err := newWafMetrics(mp)
	if err != nil {
		mp.Shutdown(ctx)
		return nil, fmt.Errorf("failed to create metrics instruments: %w", err)
	}
	return &metricsState{
		provider:    mp,
		instruments: instruments,
		shutdown:    mp.Shutdown,
	}, nil
}

// shutdownMetrics flushes and releases the provider of m in the
// background, so a collector that is down does not delay the caller.
func shutdownMetrics(m *metricsState) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := m.shutdown(ctx); err != nil {
			getLogger().Error("error shutting down meter provider", "error", err)
		}
	}()
}
