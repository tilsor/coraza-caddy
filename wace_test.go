// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	waceWAF "github.com/tilsor/wace-coraza/wace_waf"
)

// TestMain points WACE at the test configuration (no plugins, no CRS
// injection, so the WAF behaves like plain Coraza). wace_waf resolves the
// config path in its init(), before TestMain runs, so when the variable is
// not already set the test binary re-executes itself with it.
func TestMain(m *testing.M) {
	if os.Getenv(waceWAF.WACE_CONFIG_FILEPATH) != "" {
		os.Exit(m.Run())
	}

	configPath, err := filepath.Abs(filepath.Join("testdata", "waceconfig.yaml"))
	if err != nil {
		panic(err)
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Env = append(os.Environ(), waceWAF.WACE_CONFIG_FILEPATH+"="+configPath)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	var exitErr *exec.ExitError
	if err := cmd.Run(); errors.As(err, &exitErr) {
		os.Exit(exitErr.ExitCode())
	} else if err != nil {
		panic(err)
	}
	os.Exit(0)
}

// runWithWaceConfig runs the calling top-level test again in a new test
// process with WACE pointed at config, since the WACE config is process-global,
// and reports whether the caller is that process.
func runWithWaceConfig(t *testing.T, config string) bool {
	t.Helper()
	configPath, err := filepath.Abs(config)
	require.NoError(t, err)
	if os.Getenv(waceWAF.WACE_CONFIG_FILEPATH) == configPath {
		return true
	}

	// Not os.Args[0], which the Caddy tests overwrite.
	exe, err := os.Executable()
	require.NoError(t, err)
	cmd := exec.Command(exe, "-test.run=^"+t.Name()+"$", "-test.count=1")
	cmd.Env = append(os.Environ(), waceWAF.WACE_CONFIG_FILEPATH+"="+configPath)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	return false
}

func TestWacePlugins(t *testing.T) {
	if !runWithWaceConfig(t, filepath.Join("testdata", "waceconfig_plugins.yaml")) {
		return
	}

	// The first Reload of the process loads the plugins, and a plugin that
	// fails to open is only logged.
	core, logs := observer.New(zapcore.DebugLevel)
	require.NoError(t, waceWAF.Reload(slog.New(zapslog.NewHandler(core))))
	require.Equal(t, 2, logs.FilterMessage("plugin loaded").Len(),
		"build the plugins with `mage plugins`, or with `mage testRace` for -race: %v", logs.All())

	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	m := &corazaModule{
		Directives: "SecRuleEngine On",
		WaceAppConfig: &WaceAppConfig{
			ModelIDs:    []string{"param"},
			DecisionIDs: []string{"waf_only"},
		},
	}
	require.NoError(t, m.Provision(ctx))
	require.NotNil(t, m.waf)
}

func TestUnmarshalCaddyfileWace(t *testing.T) {
	tests := map[string]struct {
		config    string
		shouldErr bool
		expect    *corazaModule
	}{
		"invalid config for unexpected key": {
			config: `coraza_waf {
				unknown_key first_arg
			}`,
			shouldErr: true,
		},
		"invalid config for unexpected key in wace_config": {
			config: `coraza_waf {
				wace_config {
					unknown_key first_arg
				}
			}`,
			shouldErr: true,
		},
		"invalid config for model_ids without value": {
			config: `coraza_waf {
				wace_config {
					model_ids
				}
			}`,
			shouldErr: true,
		},
		"invalid config for blocking with value": {
			config: `coraza_waf {
				wace_config {
					blocking true
				}
			}`,
			shouldErr: true,
		},
		"invalid config for wace_config_file without value": {
			config: `coraza_waf {
				wace_config_file
			}`,
			shouldErr: true,
		},
		"invalid config for wace_exceptions_file with more than one value": {
			config: `coraza_waf {
				wace_exceptions_file first.conf second.conf
			}`,
			shouldErr: true,
		},
		"valid config with wace files": {
			config: `coraza_waf {
				wace_config_file capec.yaml
				wace_exceptions_file capec-exceptions.conf
			}`,
			expect: &corazaModule{
				Include:            []string{},
				WaceAppConfigFile:  "capec.yaml",
				WaceExceptionsFile: "capec-exceptions.conf",
			},
		},
		"valid config with wace_config": {
			config: `coraza_waf {
				directives ` + "`SecRuleEngine On`" + `
				wace_config {
					app_name Capec
					model_ids param
					decision_ids waf_only waf_only_training
					early_blocking
					blocking
				}
			}`,
			expect: &corazaModule{
				Include:    []string{},
				Directives: "SecRuleEngine On",
				WaceAppConfig: &WaceAppConfig{
					AppName:       "Capec",
					ModelIDs:      []string{"param"},
					DecisionIDs:   []string{"waf_only", "waf_only_training"},
					EarlyBlocking: true,
					Blocking:      true,
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dispenser := caddyfile.NewTestDispenser(test.config)
			m := &corazaModule{}
			err := m.UnmarshalCaddyfile(dispenser)
			if test.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			if test.expect != nil {
				require.Equal(t, test.expect, m)
			}
		})
	}
}

func TestValidateWaceConfig(t *testing.T) {
	inline := &WaceAppConfig{DecisionIDs: []string{"waf_only"}}

	tests := map[string]struct {
		module    *corazaModule
		shouldErr bool
	}{
		"no WACE options": {
			module: &corazaModule{Include: []string{"my-rules.conf"}},
		},
		"only the wace_config block": {
			module: &corazaModule{WaceAppConfig: inline},
		},
		"only wace_config_file and wace_exceptions_file": {
			module: &corazaModule{
				WaceAppConfigFile:  "capec.yaml",
				WaceExceptionsFile: "capec-exceptions.conf",
			},
		},
		"wace_config block without decision ids": {
			module:    &corazaModule{WaceAppConfig: &WaceAppConfig{AppName: "Capec"}},
			shouldErr: true,
		},
		"wace_config block and wace_config_file": {
			module:    &corazaModule{WaceAppConfig: inline, WaceAppConfigFile: "capec.yaml"},
			shouldErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			err := test.module.validateWaceConfig()
			if test.shouldErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResolveWaceAppConfig(t *testing.T) {
	t.Run("nothing set", func(t *testing.T) {
		appConfig, err := (&corazaModule{}).resolveWaceAppConfig()
		require.NoError(t, err)
		require.Nil(t, appConfig)
	})

	for _, loadCRS := range []bool{true, false} {
		t.Run(fmt.Sprintf("from the wace_config block with load_owasp_crs=%t", loadCRS), func(t *testing.T) {
			m := &corazaModule{
				LoadOWASPCRS: loadCRS,
				WaceAppConfig: &WaceAppConfig{
					AppName:     "Capec",
					ModelIDs:    []string{"param"},
					DecisionIDs: []string{"waf_only"},
					Blocking:    true,
				},
			}
			appConfig, err := m.resolveWaceAppConfig()
			require.NoError(t, err)
			require.Equal(t, &waceWAF.WaceAppConfigFileData{
				AppName:     "Capec",
				ModelIds:    []string{"param"},
				DecisionIds: []string{"waf_only"},
				Blocking:    true,
				DisableCRS:  !loadCRS,
			}, appConfig)
		})
	}

	t.Run("wace_config_file keeps disable_crs from the YAML regardless of load_owasp_crs", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "capec.yaml")
		require.NoError(t, os.WriteFile(file, []byte("decision_ids: [\"waf_only\"]\ndisable_crs: true\n"), 0o600))

		appConfig, err := (&corazaModule{LoadOWASPCRS: true, WaceAppConfigFile: file}).resolveWaceAppConfig()
		require.NoError(t, err)
		require.True(t, appConfig.DisableCRS)
	})

	t.Run("from wace_config_file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "capec.yaml")
		require.NoError(t, os.WriteFile(file, []byte(`
model_ids: ["param"]
decision_ids: ["waf_only", "waf_only_training"]
early_blocking: true
blocking: true
app_name: "Capec"
`), 0o600))

		appConfig, err := (&corazaModule{WaceAppConfigFile: file}).resolveWaceAppConfig()
		require.NoError(t, err)
		require.Equal(t, &waceWAF.WaceAppConfigFileData{
			AppName:       "Capec",
			ModelIds:      []string{"param"},
			DecisionIds:   []string{"waf_only", "waf_only_training"},
			EarlyBlocking: true,
			Blocking:      true,
		}, appConfig)
	})

	t.Run("missing wace_config_file", func(t *testing.T) {
		_, err := (&corazaModule{WaceAppConfigFile: filepath.Join(t.TempDir(), "missing.yaml")}).resolveWaceAppConfig()
		require.Error(t, err)
	})

	t.Run("malformed wace_config_file", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "capec.yaml")
		require.NoError(t, os.WriteFile(file, []byte(`model_ids: ["param"`), 0o600))

		_, err := (&corazaModule{WaceAppConfigFile: file}).resolveWaceAppConfig()
		require.Error(t, err)
	})
}

func TestComputePoolKeyWace(t *testing.T) {
	withAppConfig := func(decisionID string) *corazaModule {
		return &corazaModule{
			Directives:    "SecRuleEngine On",
			waceAppConfig: &waceWAF.WaceAppConfigFileData{AppName: "Capec", DecisionIds: []string{decisionID}},
		}
	}
	plain := &corazaModule{Directives: "SecRuleEngine On"}
	withExceptions := &corazaModule{Directives: "SecRuleEngine On", WaceExceptionsFile: "capec.conf"}

	require.Equal(t, withAppConfig("waf_only").computePoolKey(), withAppConfig("waf_only").computePoolKey())
	require.NotEqual(t, withAppConfig("waf_only").computePoolKey(), withAppConfig("waf_only_training").computePoolKey())
	require.NotEqual(t, withAppConfig("waf_only").computePoolKey(), plain.computePoolKey())
	require.NotEqual(t, withExceptions.computePoolKey(), plain.computePoolKey())
}

func TestComputePoolKeyWaceConfigVersion(t *testing.T) {
	m := &corazaModule{Directives: "SecRuleEngine On"}
	before := m.computePoolKey()

	original := waceConfigVersion
	t.Cleanup(func() { waceConfigVersion = original })
	waceConfigVersion = func() string { return original() + "-reloaded" }

	require.NotEqual(t, before, m.computePoolKey())
}
