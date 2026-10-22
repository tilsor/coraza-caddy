// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

// Copied from github.com/tilsor/ModSecIntl_wace_lib testdata/plugins/decision/waf_only.go.
// Built as a Go plugin by `mage plugins`.

// Decision Plugin that blocks based only on the WAF anomaly score

package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"

	"github.com/tilsor/ModSecIntl_wace_lib/waceapi"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const PLUGIN_NAME = "waf_only"

type wafOnlyDecision struct {
	logger atomic.Pointer[slog.Logger]
}

func NewPlugin(cfg waceapi.PluginConfig) (waceapi.DecisionPlugin, error) {
	// Create counter for plugin register
	ctx := context.Background()
	pluginCounter, err := cfg.Meter.Int64Counter("plugin_register")
	if err != nil {
		return nil, err
	}
	pluginCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("plugin_name", PLUGIN_NAME), attribute.String("plugin_type", "decision")))
	d := &wafOnlyDecision{}
	d.logger.Store(cfg.Logger)
	return d, nil
}

func (d *wafOnlyDecision) CheckResults(ctx context.Context, decisionInput waceapi.DecisionInput) (waceapi.DecisionResult, error) {
	as, ok := decisionInput.WAFdata.Scores["inbound_blocking"]
	if !ok {
		return waceapi.DecisionResult{}, fmt.Errorf("inbound_blocking score not found")
	}
	it, ok := decisionInput.WAFdata.Scores["inbound_threshold"]
	if !ok {
		return waceapi.DecisionResult{}, fmt.Errorf("inbound_threshold score not found")
	}

	d.logger.Load().Debug("WAF anomaly score", waceapi.LogKeyTxID, decisionInput.TransactionId,
		"anomaly_score", as, "anomaly_score.threshold", it)
	if decisionInput.Training {
		return waceapi.DecisionResult{Block: as >= it, Data: decisionInput}, nil
	} else {
		return waceapi.DecisionResult{Block: as >= it}, nil
	}
}

// Reload reloads the plugin (does nothing in this case)
func (d *wafOnlyDecision) Reload(cfg waceapi.PluginConfig) error {
	d.logger.Store(cfg.Logger)
	return nil
}

func (d *wafOnlyDecision) Clean() error {
	return nil
}
