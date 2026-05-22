/* Trivial Model Plugin that always returns 0 probability of attack
 */

package main

import (
	"context"

	lg "github.com/tilsor/ModSecIntl_logging/logging"
	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// InitPlugin intitalizes the plugins (does nothing in this case)
func InitPlugin(params map[string]string, meter metric.Meter) error {
	logger := lg.Get()
	logger.Printf(lg.WARN, "[trivial:InitPlugin] %v\n", params)
	// Create counter for plugin register
	ctx := context.Background()
	pluginCounter, err := meter.Int64Counter("plugin_register")
	if err != nil {
		return err
	}
	pluginCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("plugin_name", "trivial"), attribute.String("plugin_type", "model")))
	return nil
}

func InitPluginAsync(params map[string]string, meter metric.Meter, natsManager func(func(waceapi.ModelInput) (waceapi.ModelResults, error))) error {
	InitPlugin(params, meter)
	natsManager(Process)
	return nil
}

func Process(input waceapi.ModelInput) (waceapi.ModelResults, error) {
	logger := lg.Get()
	logger.TPrintf(lg.WARN, input.TransactionId, "[trivial:Process] \"%v\"\n", input.Payload)
	result := waceapi.ModelResults{
		ProbAttack: 0.0,
		Data:       input,
		// Data:       make(map[string]interface{}),
	}
	return result, nil
}

// ReloadPlugin reload the plugin (does nothing in this case)
func ReloadPlugin(params map[string]string, meter metric.Meter) error {
	logger := lg.Get()
	logger.Printf(lg.WARN, "[trivial:ReloadPlugin] %v\n", params)
	return nil
}
