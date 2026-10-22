// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

// This file holds the Tilsor WACE integration and the other additions of this
// fork, so that coraza.go stays close to upstream and merges stay simple.
// coraza.go only calls into it from a few hook points.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.yaml.in/yaml/v3"

	waceWAF "github.com/tilsor/wace-coraza/wace_waf"
)

// WaceAppConfig holds the per-application WACE settings declared inline in the
// Caddyfile, as an alternative to pointing at a waceappconfig.yaml file.
type WaceAppConfig struct {
	AppName       string   `json:"app_name,omitempty"`
	ModelIDs      []string `json:"model_ids,omitempty"`
	DecisionIDs   []string `json:"decision_ids,omitempty"`
	EarlyBlocking bool     `json:"early_blocking,omitempty"`
	Blocking      bool     `json:"blocking,omitempty"`
}

// provisionWace loads the WACE general config and resolves the app config. It
// has to run before computePoolKey, which hashes the resolved app config.
func (m *corazaModule) provisionWace() error {
	if err := waceWAF.Reload(nil); err != nil {
		return err
	}

	if err := m.validateWaceConfig(); err != nil {
		return err
	}

	appConfig, err := m.resolveWaceAppConfig()
	if err != nil {
		return err
	}
	m.waceAppConfig = appConfig
	return nil
}

// validateWaceConfig rejects configs that set the WACE app config from more
// than one source, since resolveWaceAppConfig would silently ignore the file.
func (m *corazaModule) validateWaceConfig() error {
	if m.WaceAppConfig != nil && m.WaceAppConfigFile != "" {
		return errors.New("the WACE app config is set more than once, pick one of: wace_config, wace_config_file")
	}

	if m.WaceAppConfig != nil && len(m.WaceAppConfig.DecisionIDs) == 0 {
		return errors.New("'wace_config' requires at least one id in 'decision_ids'")
	}

	return nil
}

// resolveWaceAppConfig returns the WACE app config from the inline block or
// from wace_config_file, or nil when neither is set.
func (m *corazaModule) resolveWaceAppConfig() (*waceWAF.WaceAppConfigFileData, error) {
	if w := m.WaceAppConfig; w != nil {
		return &waceWAF.WaceAppConfigFileData{
			AppName:       w.AppName,
			ModelIds:      w.ModelIDs,
			DecisionIds:   w.DecisionIDs,
			EarlyBlocking: w.EarlyBlocking,
			// Assumes load_owasp_crs goes along with an Include of the CRS rules in
			// 'directives'. Enabling it without including them makes WAF creation
			// fail, since WACE updates CRS rule ids that were never loaded.
			DisableCRS: !m.LoadOWASPCRS,
			Blocking:   w.Blocking,
		}, nil
	}

	if m.WaceAppConfigFile == "" {
		return nil, nil
	}

	data, err := os.ReadFile(m.WaceAppConfigFile)
	if err != nil {
		return nil, fmt.Errorf("reading wace_config_file: %w", err)
	}

	var appConfig waceWAF.WaceAppConfigFileData
	if err := yaml.Unmarshal(data, &appConfig); err != nil {
		return nil, fmt.Errorf("parsing wace_config_file %q: %w", m.WaceAppConfigFile, err)
	}

	return &appConfig, nil
}

// newWaceWAFConfig returns the base WAF config with the WACE options set. They
// are only available on the concrete config type, so they have to be set
// before the chain widens to coraza.WAFConfig.
func (m *corazaModule) newWaceWAFConfig() coraza.WAFConfig {
	config := waceWAF.NewWaceWAFConfig()
	if m.waceAppConfig != nil {
		config.WithWaceAppConfig(*m.waceAppConfig)
	}
	if m.WaceExceptionsFile != "" {
		config.WithExceptionsFromFile(m.WaceExceptionsFile)
	}
	return config
}

// newWaceWAF creates a WACE WAF. On failure it returns a nil coraza.WAF rather than
// a typed nil *WaceWAF, which would not compare equal to nil.
func newWaceWAF(config coraza.WAFConfig) (coraza.WAF, error) {
	waf, err := waceWAF.NewWAF(config)
	if err != nil {
		return nil, err
	}
	return waf, nil
}

// writeWacePoolKey adds the WACE options to the WAF pool key.
func (m *corazaModule) writeWacePoolKey(h io.Writer) {
	// Hashing the resolved content rather than the file path means an edit to
	// wace_config_file also yields a fresh WAF on reload.
	if m.waceAppConfig != nil {
		fmt.Fprintf(h, "wace-app:%+v\x00", *m.waceAppConfig)
	}

	if m.WaceExceptionsFile != "" {
		fmt.Fprintf(h, "wace-exceptions:%s\x00", m.WaceExceptionsFile)
	}
}

// unmarshalWaceKey parses the Caddyfile keys added by WACE, and rejects any
// other key, since it is called for the keys upstream does not know.
func (m *corazaModule) unmarshalWaceKey(d *caddyfile.Dispenser, key string) error {
	switch key {
	case "wace_config_file", "wace_exceptions_file":
		var value string
		if !d.Args(&value) {
			// not enough args
			return d.ArgErr()
		}

		if d.NextArg() {
			// too many args
			return d.ArgErr()
		}

		if key == "wace_config_file" {
			m.WaceAppConfigFile = value
		} else {
			m.WaceExceptionsFile = value
		}
	case "wace_config":
		if d.NextArg() {
			return d.ArgErr()
		}
		return m.unmarshalWaceAppConfig(d)
	default:
		return d.Errf("invalid key %q", key)
	}

	return nil
}

// unmarshalWaceAppConfig parses the 'wace_config' block, which mirrors the
// fields of a waceappconfig.yaml file except disable_crs, derived from
// load_owasp_crs. Booleans are bare flags: their presence turns the option on,
// matching the YAML file where an absent key means false.
func (m *corazaModule) unmarshalWaceAppConfig(d *caddyfile.Dispenser) error {
	appConfig := &WaceAppConfig{}

	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch key := d.Val(); key {
		case "app_name":
			if !d.Args(&appConfig.AppName) {
				return d.ArgErr()
			}
			if d.NextArg() {
				return d.ArgErr()
			}
		case "model_ids", "decision_ids":
			ids := d.RemainingArgs()
			if len(ids) == 0 {
				return d.ArgErr()
			}
			if key == "model_ids" {
				appConfig.ModelIDs = append(appConfig.ModelIDs, ids...)
			} else {
				appConfig.DecisionIDs = append(appConfig.DecisionIDs, ids...)
			}
		case "early_blocking", "blocking":
			if d.NextArg() {
				return d.ArgErr()
			}
			switch key {
			case "early_blocking":
				appConfig.EarlyBlocking = true
			case "blocking":
				appConfig.Blocking = true
			}
		default:
			return d.Errf("invalid key %q in wace_config block", key)
		}
	}

	m.WaceAppConfig = appConfig
	return nil
}

// defaultTxID returns the transaction ID used when tx_id_req_header does not
// supply one: Caddy's request UUID, so WAF logs correlate with access logs, or
// a random ID when there is none.
func defaultTxID(r *http.Request) string {
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		if id, _ := repl.GetString("http.request.uuid"); id != "" {
			return id
		}
	}
	return randomString(16)
}

type errorLogJSON struct {
	File       string   `json:"file"`
	Line       int      `json:"line"`
	ID         int      `json:"rule_id"`
	Revision   string   `json:"revision"`
	Message    string   `json:"message"`
	Data       string   `json:"data"`
	Severity   string   `json:"severity"`
	Version    string   `json:"version"`
	Maturity   int      `json:"maturity"`
	Accuracy   int      `json:"accuracy"`
	RemoteIP   string   `json:"remote_ip"`
	Disruptive bool     `json:"disruptive"`
	Tags       []string `json:"tags"`
	Host       string   `json:"host"`
	URI        string   `json:"uri"`
	RequestID  string   `json:"request_id"`
}

// MarshalLogObject lets zap encode errorLogJSON's fields directly onto the
// log line (via zap.Inline) instead of as an escaped JSON string message.
func (e errorLogJSON) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("file", e.File)
	enc.AddInt("line", e.Line)
	enc.AddInt("rule_id", e.ID)
	enc.AddString("revision", e.Revision)
	enc.AddString("data", e.Data)
	enc.AddString("severity", e.Severity)
	enc.AddString("version", e.Version)
	enc.AddInt("maturity", e.Maturity)
	enc.AddInt("accuracy", e.Accuracy)
	enc.AddString("remote_ip", e.RemoteIP)
	enc.AddBool("disruptive", e.Disruptive)
	if err := enc.AddArray("tags", zapcore.ArrayMarshalerFunc(func(aenc zapcore.ArrayEncoder) error {
		for _, t := range e.Tags {
			aenc.AppendString(t)
		}
		return nil
	})); err != nil {
		return err
	}
	enc.AddString("host", e.Host)
	enc.AddString("uri", e.URI)
	enc.AddString("request_id", e.RequestID)
	return nil
}

func buildErrorLog(mr types.MatchedRule) errorLogJSON {
	r := mr.Rule()
	return errorLogJSON{
		File:       r.File(),
		Line:       r.Line(),
		ID:         r.ID(),
		Revision:   r.Revision(),
		Message:    mr.Message(),
		Data:       mr.Data(),
		Severity:   r.Severity().String(),
		Version:    r.Version(),
		Maturity:   r.Maturity(),
		Accuracy:   r.Accuracy(),
		RemoteIP:   mr.ClientIPAddress(),
		Host:       mr.ServerIPAddress(),
		Disruptive: mr.Disruptive(),
		Tags:       r.Tags(),
		URI:        mr.URI(),
		RequestID:  mr.TransactionID(),
	}
}

// newErrorCb logs each matched rule as structured fields rather than as
// upstream's single ErrorLog string.
func newErrorCb(logger *zap.Logger) func(types.MatchedRule) {
	return func(mr types.MatchedRule) {
		eLog := buildErrorLog(mr)
		field := zap.Inline(eLog)
		switch mr.Rule().Severity() {
		case types.RuleSeverityEmergency,
			types.RuleSeverityAlert,
			types.RuleSeverityCritical,
			types.RuleSeverityError:
			logger.Error(eLog.Message, field)
		case types.RuleSeverityWarning:
			logger.Warn(eLog.Message, field)
		case types.RuleSeverityNotice, types.RuleSeverityInfo:
			logger.Info(eLog.Message, field)
		case types.RuleSeverityDebug:
			logger.Debug(eLog.Message, field)
		default:
			logger.Warn(eLog.Message, field)
		}
	}
}
