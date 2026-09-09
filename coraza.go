// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
	"github.com/jcchavezs/mergefs"
	mergefsio "github.com/jcchavezs/mergefs/io"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	waceWAF "github.com/tilsor/wace-coraza/wace_waf"
)

// wafPool is a process-global pool that allows WAF instances to be shared
// across Caddy config reloads. When two consecutive configs use the same
// WAF configuration, the pool returns the existing WAF instead of building
// a new one, saving both memory and CPU.
var wafPool = caddy.NewUsagePool()

func init() {
	caddy.RegisterModule(corazaModule{})
	httpcaddyfile.RegisterHandlerDirective("coraza_waf", parseCaddyfile)
}

// pooledWAF wraps a coraza.WAF so it can be stored in a caddy.UsagePool.
// It implements caddy.Destructor so the pool can clean it up when all
// references are released.
type pooledWAF struct {
	waf coraza.WAF
}

func (p *pooledWAF) Destruct() error {
	var err error
	if c, ok := p.waf.(io.Closer); ok {
		if cerr := c.Close(); cerr != nil {
			err = fmt.Errorf("closing WAF: %w", cerr)
		}
	}
	p.waf = nil
	return err
}

// corazaModule is a Web Application Firewall implementation for Caddy.
type corazaModule struct {
	// deprecated
	Include      []string `json:"include"`
	Directives   string   `json:"directives"`
	LoadOWASPCRS bool     `json:"load_owasp_crs"`

	logger  *zap.Logger
	waf     coraza.WAF
	poolKey string
}

// CaddyModule returns the Caddy module information.
func (corazaModule) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf",
		New: func() caddy.Module { return new(corazaModule) },
	}
}

// Provision implements caddy.Provisioner.
func (m *corazaModule) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger(m)
	m.poolKey = m.computePoolKey()

	val, loaded, err := wafPool.LoadOrNew(m.poolKey, func() (caddy.Destructor, error) {
		waf, err := m.buildWAF()
		if err != nil {
			return nil, err
		}
		return &pooledWAF{waf: waf}, nil
	})
	if err != nil {
		return err
	}

	m.waf = val.(*pooledWAF).waf
	if loaded {
		m.logger.Info("reusing existing WAF instance from pool")
	}
	return nil
}

// buildWAF creates a new coraza.WAF from the module's configuration.
func (m *corazaModule) buildWAF() (coraza.WAF, error) {
	config := waceWAF.NewWAFConfig().
		WithErrorCallback(newErrorCb(m.logger)).
		WithDebugLogger(newLogger(m.logger))

	if m.LoadOWASPCRS {
		config = config.WithRootFS(mergefs.Merge(coreruleset.FS, mergefsio.OSFS))
	}

	if m.Directives != "" {
		config = config.WithDirectives(m.Directives)
	}

	if len(m.Include) > 0 {
		m.logger.Warn("'include' field is deprecated, please use the Include directive inside 'directives' field instead")
		for _, file := range m.Include {
			if strings.Contains(file, "*") {
				m.logger.Debug("Preparing to expand glob", zap.String("pattern", file))
				// we get files as expandables globs (with wildcard patterns)
				fs, err := filepath.Glob(file)
				if err != nil {
					return nil, err
				}
				m.logger.Debug("Glob expanded", zap.String("pattern", file), zap.Strings("files", fs))
				for _, f := range fs {
					config = config.WithDirectivesFromFile(f)
				}
			} else {
				m.logger.Debug("File was not a pattern, compiling it", zap.String("file", file))
				config = config.WithDirectivesFromFile(file)
			}
		}
	}

	return waceWAF.NewWAF(config)
}

// computePoolKey returns a deterministic key derived from the configuration
// fields that affect WAF construction. Two modules with identical configs
// will produce the same key, enabling WAF reuse across reloads.
func (m *corazaModule) computePoolKey() string {
	h := sha256.New()
	h.Write([]byte(m.Directives))
	h.Write([]byte{0}) // separator

	sorted := make([]string, len(m.Include))
	copy(sorted, m.Include)
	sort.Strings(sorted)
	for _, inc := range sorted {
		h.Write([]byte(inc))
		h.Write([]byte{0})
	}

	if m.LoadOWASPCRS {
		h.Write([]byte("crs"))
	}
	return fmt.Sprintf("coraza-waf-%x", h.Sum(nil))
}

// Validate implements caddy.Validator.
func (m *corazaModule) Validate() error {
	return nil
}

// Cleanup implements caddy.CleanerUpper.
func (m *corazaModule) Cleanup() error {
	_, err := wafPool.Delete(m.poolKey)
	return err
}

var errInterruptionTriggered = errors.New("interruption triggered")

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m corazaModule) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return next.ServeHTTP(w, r)
	}

	id, _ := repl.GetString("http.request.uuid")
	// id := randomString(16)
	tx := m.waf.NewTransactionWithID(id)
	defer func() {
		tx.ProcessLogging()
		if err := tx.Close(); err != nil {
			m.logger.Warn("Failed to close the transaction", zap.String("tx_id", tx.ID()), zap.Error(err))
		}
	}()

	// Early return, Coraza is not going to process any rule
	if tx.IsRuleEngineOff() {
		// response writer is not going to be wrapped, but used as-is
		// to generate the response
		return next.ServeHTTP(w, r)
	}

	// repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	// repl.Set("http.transaction_id", id)

	server := r.Context().Value(caddyhttp.ServerCtxKey).(*caddyhttp.Server)
	caddyhttp.PrepareRequest(r, repl, w, server)

	// ProcessRequest is just a wrapper around ProcessConnection, ProcessURI,
	// ProcessRequestHeaders and ProcessRequestBody.
	// It fails if any of these functions returns an error and it stops on interruption.
	if it, err := processRequest(tx, r); err != nil {
		return caddyhttp.HandlerError{
			StatusCode: http.StatusInternalServerError,
			ID:         tx.ID(),
			Err:        err,
		}
	} else if it != nil {
		m.logger.Error("WAF rule violation detected",
			zap.String("hostname", r.Host),
			zap.String("uri", r.RequestURI),
			zap.String("client_ip", r.RemoteAddr),
			zap.String("unique_id", tx.ID()),
		)
		return caddyhttp.HandlerError{
			StatusCode: obtainStatusCodeFromInterruptionOrDefault(it, http.StatusOK),
			ID:         tx.ID(),
			Err:        errInterruptionTriggered,
		}
	}

	ww, processResponse := wrap(w, r, tx)

	// We continue with the other middlewares by catching the response
	if err := next.ServeHTTP(ww, r); err != nil {
		return err
	}

	return processResponse(tx, r)
}

// Unmarshal Caddyfile implements caddyfile.Unmarshaler.
func (m *corazaModule) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	if !d.Next() {
		return d.Err("expected token following filter")
	}
	m.Include = []string{}
	for d.NextBlock(0) {
		key := d.Val()
		switch key {
		case "load_owasp_crs":
			if d.NextArg() {
				return d.ArgErr()
			}
			m.LoadOWASPCRS = true
		case "directives", "include":
			var value string
			if !d.Args(&value) {
				// not enough args
				return d.ArgErr()
			}

			if d.NextArg() {
				// too many args
				return d.ArgErr()
			}

			switch key {
			case "include":
				m.Include = append(m.Include, value)
			case "directives":
				m.Directives = value
			}
		default:
			return d.Errf("invalid key %q", key)
		}
	}

	return nil
}

// parseCaddyfile unmarshals tokens from h into a new Middleware.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m corazaModule
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
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

// Interface guards
var (
	_ caddy.Provisioner           = (*corazaModule)(nil)
	_ caddy.Validator             = (*corazaModule)(nil)
	_ caddy.CleanerUpper          = (*corazaModule)(nil)
	_ caddyhttp.MiddlewareHandler = (*corazaModule)(nil)
	_ caddyfile.Unmarshaler       = (*corazaModule)(nil)
)
