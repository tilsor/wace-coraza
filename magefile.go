//go:build mage

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

const pluginDir = "wace_waf/testdata/plugins"

// Plugins builds all test plugins without coverage instrumentation.
func Plugins() error {
	return buildPlugins()
}

// pluginsCover builds all test plugins with coverage instrumentation.
func pluginsCover() error {
	return buildPlugins("-cover")
}

// buildPlugins compiles every .go file under testdata/plugins/model and
// testdata/plugins/decision into a .so plugin. Pass "-cover" to instrument
// for coverage.
func buildPlugins(extraFlags ...string) error {
	sources, err := filepath.Glob(filepath.Join(pluginDir, "*.go"))
	if err != nil {
		return err
	}
	for _, src := range sources {
		out := strings.TrimSuffix(src, ".go") + ".so"
		args := []string{"build", "-buildmode=plugin"}
		args = append(args, extraFlags...)
		args = append(args, "-o", out, src)
		fmt.Printf("building %s\n", out)
		if err := sh.RunV("go", args...); err != nil {
			return err
		}
	}
	return nil
}

// Test builds the plugins and runs the full test suite.
func Test() error {
	mg.Deps(Plugins)
	return sh.RunV("go", "test", "./...", "-v", "-count=1")
}

// TestCoverage builds coverage-instrumented plugins and runs the test suite
// with coverage reporting across all packages.
func TestCoverage() error {
	mg.Deps(pluginsCover)
	return sh.RunV("go", "test", "-cover", "./...", "-v", "-count=1", "-coverprofile=coverage.out")
}

// Clean removes all compiled plugin .so files.
func Clean() error {
	for _, pattern := range []string{
		filepath.Join(pluginDir, "model", "*.so"),
		filepath.Join(pluginDir, "decision", "*.so"),
	} {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return err
		}
		for _, f := range matches {
			fmt.Printf("removing %s\n", f)
			if err := os.Remove(f); err != nil {
				return err
			}
		}
	}
	return nil
}
