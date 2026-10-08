// Decision Plugin that uses weighted sum algorithm to decide if a transaction should be blocked

package main

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type weightedSumDecision struct {
	logger    atomic.Pointer[slog.Logger]
	mu        sync.RWMutex
	threshold float64
}

func NewPlugin(cfg waceapi.PluginConfig) (waceapi.DecisionPlugin, error) {
	d := &weightedSumDecision{}
	if err := d.Reload(cfg); err != nil {
		return nil, err
	}

	// Create counter for plugin register
	ctx := context.Background()
	pluginCounter, err := cfg.Meter.Int64Counter("plugin_register")
	if err != nil {
		return nil, err
	}
	pluginCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("plugin_name", "weighted_sum_training"), attribute.String("plugin_type", "decision")))
	return d, nil
}

func (d *weightedSumDecision) CheckResults(ctx context.Context, decisionInput waceapi.DecisionInput) (waceapi.DecisionResult, error) {
	var weightedSum float64 = 0
	var weightsSum float64 = 0
	for key, value := range decisionInput.Results {
		weightedSum += value.ProbAttack * decisionInput.ModelWeight[key]
		weightsSum += decisionInput.ModelWeight[key]
	}

	as, ok := decisionInput.WAFdata.Scores["inbound_blocking"]
	if !ok {
		return waceapi.DecisionResult{}, fmt.Errorf("inbound_blocking score not found")
	}
	it, ok := decisionInput.WAFdata.Scores["inbound_threshold"]
	if !ok {
		return waceapi.DecisionResult{}, fmt.Errorf("inbound_threshold score not found")
	}

	wafWeight := decisionInput.WAFWeight

	logger := d.logger.Load().With(waceapi.LogKeyTxID, decisionInput.TransactionId)
	logger.Debug("WAF anomaly score", "anomaly_score", as, "anomaly_score.threshold", it)

	if as >= it {
		weightedSum += wafWeight
	} else {
		weightedSum += (as / it) * wafWeight
	}
	weightsSum += wafWeight

	weightedSum /= weightsSum

	d.mu.RLock()
	threshold := d.threshold
	d.mu.RUnlock()

	logger.Debug("weighted sum", "weighted_sum", weightedSum, "threshold", threshold)
	return waceapi.DecisionResult{Block: weightedSum > threshold, Data: decisionInput.WAFdata}, nil
}

// Reload reads the optional "threshold" param (default 0.5). The logger
// is replaced even if the params are rejected.
func (d *weightedSumDecision) Reload(cfg waceapi.PluginConfig) error {
	d.logger.Store(cfg.Logger)
	threshold := 0.5
	if stringThreshold, ok := cfg.Params["threshold"]; ok {
		var err error
		threshold, err = strconv.ParseFloat(stringThreshold, 64)
		if err != nil {
			return fmt.Errorf("error parsing threshold parameter: %v", err)
		}
	}
	d.mu.Lock()
	d.threshold = threshold
	d.mu.Unlock()
	return nil
}

func (d *weightedSumDecision) Clean() error {
	return nil
}
