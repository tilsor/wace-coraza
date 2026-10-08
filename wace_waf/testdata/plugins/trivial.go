/* Trivial Model Plugin that always returns 0.0 probability of attack
 */

package main

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

type trivialModel struct {
	logger atomic.Pointer[slog.Logger]
}

// NewPlugin intitalizes the plugin (does nothing in this case)
func NewPlugin(cfg waceapi.PluginConfig) (waceapi.ModelPlugin, error) {
	cfg.Logger.Warn("NewPlugin", "params", cfg.Params)
	// Create counter for plugin register
	ctx := context.Background()
	pluginCounter, err := cfg.Meter.Int64Counter("plugin_register")
	if err != nil {
		return nil, err
	}
	pluginCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("plugin_name", "trivial"), attribute.String("plugin_type", "model")))
	m := &trivialModel{}
	m.logger.Store(cfg.Logger)
	return m, nil
}

func (m *trivialModel) Process(ctx context.Context, input waceapi.ModelInput) (waceapi.ModelResults, error) {
	m.logger.Load().Debug("Process", waceapi.LogKeyTxID, input.TransactionId)
	result := waceapi.ModelResults{
		ProbAttack: 0.0,
		Data:       input,
	}
	return result, nil
}

// Reload reloads the plugin (does nothing in this case)
func (m *trivialModel) Reload(cfg waceapi.PluginConfig) error {
	m.logger.Store(cfg.Logger)
	cfg.Logger.Warn("Reload", "params", cfg.Params)
	return nil
}

func (m *trivialModel) Clean() error {
	return nil
}
