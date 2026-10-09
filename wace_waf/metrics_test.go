package waceWAF

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

func TestNewMetricsNoopWithoutURL(t *testing.T) {
	m, err := newMetrics(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := m.provider.(noop.MeterProvider); !ok {
		t.Errorf("expected a noop provider, got %T", m.provider)
	}
}

func TestNewMetricsOTLPWithURL(t *testing.T) {
	// the gRPC connection is lazy, so no collector is needed
	m, err := newMetrics(context.Background(), "localhost:4317")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := m.provider.(*sdkmetric.MeterProvider); !ok {
		t.Errorf("expected an SDK provider, got %T", m.provider)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	m.shutdown(ctx)
}
