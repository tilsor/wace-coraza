// Decision Plugin that uses weighted sum algorithm to decide if a transaction should be blocked

package main

import (
	"context"
	"fmt"
	"strconv"

	lg "github.com/tilsor/ModSecIntl_logging/logging"
	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var threshold float64

func InitPlugin(params map[string]string, meter metric.Meter) error {
	var err error
	stringThreshold, ok := params["threshold"]
	if !ok {
		threshold = 0.5
	} else {
		threshold, err = strconv.ParseFloat(stringThreshold, 64)
		if err != nil {
			return fmt.Errorf("error parsing threshold parameter: %v", err)
		}
	}

	// Create counter for plugin register
	ctx := context.Background()
	pluginCounter, err := meter.Int64Counter("plugin_register")
	if err != nil {
		return err
	}
	pluginCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("plugin_name", "weighted_sum"), attribute.String("plugin_type", "decision")))
	return nil
}

func CheckResults(decisionInput waceapi.DecisionInput) (waceapi.DecisionResult, error) {
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

	logger := lg.Get()
	logger.TPrintf(lg.DEBUG, decisionInput.TransactionId, "weighted_sum | anomaly score: %v anomaly score threshold: %v", as, it)

	if as >= it {
		weightedSum += wafWeight
	} else {
		weightedSum += (as / it) * wafWeight
	}
	weightsSum += wafWeight

	weightedSum /= weightsSum

	logger.TPrintf(lg.DEBUG, decisionInput.TransactionId, "weighted_sum | weighted sum: %v threshold: %v", weightedSum, threshold)
	return waceapi.DecisionResult{Block: weightedSum > threshold}, nil
}

// ReloadPlugin reload the plugin
func ReloadPlugin(params map[string]string, meter metric.Meter) error {
	return nil
}
