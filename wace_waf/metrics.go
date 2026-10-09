package waceWAF

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// meterScope is the instrumentation scope name of the WACE WAF metrics.
const meterScope = "waceWAF"

// metricsState holds the meter provider passed to the WACE core, the meter
// WACE WAF records with, and the function that flushes and releases the
// provider. They are stored together so they are always replaced at once.
type metricsState struct {
	provider metric.MeterProvider
	meter    metric.Meter
	shutdown func(context.Context) error
}

// currentMetrics holds the current metrics state. It is replaced by NewWAF
// when otel_url changes, while transactions may be recording on it.
var currentMetrics atomic.Pointer[metricsState]

// getMeter returns the current WACE WAF meter.
func getMeter() metric.Meter {
	return currentMetrics.Load().meter
}

func init() {
	currentMetrics.Store(newNoopMetrics())
}

var serviceName = semconv.ServiceNameKey.String("waceWAF-service")

// newNoopMetrics returns a metrics state that records nothing.
func newNoopMetrics() *metricsState {
	mp := noop.NewMeterProvider()
	return &metricsState{
		provider: mp,
		meter:    mp.Meter(meterScope),
		shutdown: func(context.Context) error { return nil },
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
	return &metricsState{
		provider: mp,
		meter:    mp.Meter(meterScope),
		shutdown: mp.Shutdown,
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
