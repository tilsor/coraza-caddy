// Copyright 2026 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

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
