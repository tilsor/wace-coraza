package waceWAF

import (
	"context"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
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
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	m.shutdown(ctx)
}

func TestNewResourceServiceName(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "")
	res, err := newResource(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := res.Set().Value(semconv.ServiceNameKey); got.AsString() != serviceName {
		t.Errorf("expected service name %q, got %q", serviceName, got.AsString())
	}
	if _, ok := res.Set().Value(semconv.TelemetrySDKNameKey); !ok {
		t.Errorf("expected the telemetry SDK attributes, got %v", res)
	}
}

func TestNewResourceServiceNameFromEnv(t *testing.T) {
	t.Setenv("OTEL_SERVICE_NAME", "my-waf")
	res, err := newResource(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, _ := res.Set().Value(semconv.ServiceNameKey); got.AsString() != "my-waf" {
		t.Errorf("expected service name %q from the environment, got %q", "my-waf", got.AsString())
	}
}

func TestNewMetricsMalformedResourceAttributes(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "malformed")
	m, err := newMetrics(context.Background(), "localhost:4317")
	if err != nil {
		t.Fatalf("a malformed OTEL_RESOURCE_ATTRIBUTES should not fail, got: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	m.shutdown(ctx)
}

// useManualReader replaces the current metrics with ones read by a manual
// reader until the test ends.
func useManualReader(t *testing.T) *sdkmetric.ManualReader {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	instruments, err := newWafMetrics(mp)
	if err != nil {
		t.Fatalf("unexpected error creating instruments: %v", err)
	}
	old := currentMetrics.Swap(&metricsState{provider: mp, instruments: instruments, shutdown: mp.Shutdown})
	t.Cleanup(func() { currentMetrics.Store(old) })
	return reader
}

// collectMetrics returns the metrics recorded by reader, by name.
func collectMetrics(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("unexpected error collecting metrics: %v", err)
	}
	ret := make(map[string]metricdata.Metrics)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			ret[m.Name] = m
		}
	}
	return ret
}

func TestTransactionRecordsMetrics(t *testing.T) {
	configFilePath = "testdata/config/waceconfig_block_transaction.yaml"
	gConfig = nil
	defer resetWACE()

	wafConf := NewWAFConfig().WithDirectivesFromFile("testdata/config/directives.conf").
		WithDirectivesFromFile("../coreruleset/crs-setup.conf.example").
		WithDirectivesFromFile("../coreruleset/rules/*.conf").
		WithDirectives("SecAction \"id:15,phase:1,pass,nolog,setvar:'tx.blocking_inbound_anomaly_score=10',setvar:'tx.inbound_anomaly_score_threshold=5'\"")
	waf, err := NewWAF(wafConf)
	if err != nil {
		t.Fatalf("Error creating WAF: %v", err)
	}
	reader := useManualReader(t)

	tx := waf.NewTransaction()
	defer tx.Close()
	tx.ProcessURI("http://localhost:8090", "GET", "HTTP/1.1")
	tx.AddRequestHeader("content-type", "application/x-www-form-urlencoded")
	tx.ProcessRequestHeaders()
	tx.ReadRequestBodyFrom(strings.NewReader("test"))
	tx.ProcessRequestBody()
	tx.AddResponseHeader("content-type", "application/x-www-form-urlencoded")
	tx.ProcessResponseHeaders(200, "HTTP/1.1")
	tx.WriteResponseBody([]byte("test"))
	tx.ProcessResponseBody()
	tx.ProcessLogging()

	got := collectMetrics(t, reader)
	for _, name := range []string{
		"wace.waf.exceptions.duration",
		"wace.waf.request.body.read.duration",
		"wace.waf.response.body.write.duration",
		"wace.waf.crs.duration",
		"wace.waf.integration.duration",
		"wace.waf.transaction.duration",
	} {
		m, ok := got[name]
		if !ok {
			t.Errorf("metric %s was not recorded", name)
			continue
		}
		if m.Unit != "s" {
			t.Errorf("metric %s: expected unit s, got %q", name, m.Unit)
		}
	}

	// exceptions are evaluated in every phase
	if phases := phasesOf(t, got["wace.waf.exceptions.duration"]); !reflect.DeepEqual(phases, []int64{1, 2, 3, 4}) {
		t.Errorf("expected exceptions recorded in phases 1 to 4, got %v", phases)
	}

	// the request is blocked by WACE in every phase
	if phases := phasesOf(t, got["wace.waf.transaction.blocked"]); !reflect.DeepEqual(phases, []int64{1, 2, 3, 4}) {
		t.Errorf("expected blocked transactions in phases 1 to 4, got %v", phases)
	}

	// ProcessLogging records once per transaction, with the status of the
	// last interruption
	processed, ok := got["wace.waf.transaction.processed"].Data.(metricdata.Sum[int64])
	if !ok || len(processed.DataPoints) != 1 {
		t.Fatalf("expected one processed data point, got %+v", got["wace.waf.transaction.processed"].Data)
	}
	dp := processed.DataPoints[0]
	if dp.Value != 1 {
		t.Errorf("expected one processed transaction, got %d", dp.Value)
	}
	if status, _ := dp.Attributes.Value(semconv.HTTPResponseStatusCodeKey); status.AsInt64() != 403 {
		t.Errorf("expected status code 403, got %v", status.AsInt64())
	}
}

// phasesOf returns the sorted values of the phase attribute of the data
// points of m, a histogram or a counter.
func phasesOf(t *testing.T, m metricdata.Metrics) []int64 {
	t.Helper()
	var sets []attribute.Set
	switch data := m.Data.(type) {
	case metricdata.Histogram[float64]:
		for _, dp := range data.DataPoints {
			sets = append(sets, dp.Attributes)
		}
	case metricdata.Sum[int64]:
		for _, dp := range data.DataPoints {
			sets = append(sets, dp.Attributes)
		}
	default:
		t.Fatalf("metric %s: unexpected data %T", m.Name, m.Data)
	}
	var phases []int64
	for _, set := range sets {
		if v, ok := set.Value(attrPhase); ok {
			phases = append(phases, v.AsInt64())
		}
	}
	slices.Sort(phases)
	return phases
}
