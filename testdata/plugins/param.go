// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Copied from github.com/tilsor/ModSecIntl_wace_lib testdata/plugins/model/param.go.
// Built as a Go plugin by `mage plugins`.

/* Param Model Plugin that returns the probability of attack given in its "result" param
 */

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

type paramModel struct {
	logger atomic.Pointer[slog.Logger]
	mu     sync.RWMutex
	result float64
}

// NewPlugin reads the "result" param and sets the probability that Process will return.
func NewPlugin(cfg waceapi.PluginConfig) (waceapi.ModelPlugin, error) {
	cfg.Logger.Warn("NewPlugin", "params", cfg.Params)
	m := &paramModel{}
	m.logger.Store(cfg.Logger)
	if err := m.Reload(cfg); err != nil {
		return nil, err
	}
	ctx := context.Background()
	pluginCounter, err := cfg.Meter.Int64Counter("plugin_register")
	if err != nil {
		return nil, err
	}
	pluginCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("plugin_name", "param"), attribute.String("plugin_type", "model")))
	return m, nil
}

func (m *paramModel) Process(ctx context.Context, input waceapi.ModelInput) (waceapi.ModelResults, error) {
	m.logger.Load().Warn("Process", waceapi.LogKeyTxID, input.TransactionId, "payload", input.Payload)
	m.mu.RLock()
	defer m.mu.RUnlock()
	return waceapi.ModelResults{
		ProbAttack: m.result,
		// Data:       input,
	}, nil
}

// Reload updates the probability returned by Process from the new params.
func (m *paramModel) Reload(cfg waceapi.PluginConfig) error {
	m.logger.Store(cfg.Logger)
	cfg.Logger.Warn("Reload", "params", cfg.Params)
	resultString, ok := cfg.Params["result"]
	if !ok {
		return fmt.Errorf("result parameter not found")
	}
	result, err := strconv.ParseFloat(resultString, 64)
	if err != nil {
		return fmt.Errorf("error parsing result parameter: %v", err)
	}
	m.mu.Lock()
	m.result = result
	m.mu.Unlock()
	return nil
}

func (m *paramModel) Clean() error {
	return nil
}
