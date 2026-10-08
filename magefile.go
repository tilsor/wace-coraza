//go:build mage

package main

import (
	"errors"
	"fmt"
	"io"
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

// pluginsRace builds all test plugins with the race detector. A test
// binary built with -race only loads plugins built with -race, and the
// other way around.
func pluginsRace() error {
	return buildPlugins("-race")
}

// buildPlugins compiles every .go file under wace_waf/testdata/plugins into
// a .so plugin. Pass "-cover" to instrument for coverage.
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

// TestRace builds race-instrumented plugins and runs the full test suite
// with the race detector. The plain plugins are rebuilt afterwards, even
// if the tests fail, so a later plain `go test` still loads them.
func TestRace() error {
	if err := pluginsRace(); err != nil {
		return err
	}
	testErr := sh.RunV("go", "test", "-race", "./...", "-count=1")
	return errors.Join(testErr, Plugins())
}

// Bench builds the plugins and runs the benchmarks, printing the results
// and saving them for benchstat. It reads these environment variables:
//
//	BENCH                benchmark regexp (default ".")
//	BENCH_COUNT          runs of each benchmark (default 10)
//	BENCH_OUT            output file (default bench.txt)
//	WACE_BENCH_NATS_URL  NATS server for BenchmarkWaceTransactionsNATS,
//	                     which is skipped when it is not set
//
// To compare against a baseline: save one run as the baseline, make the
// changes, run again and compare both with
// `go run golang.org/x/perf/cmd/benchstat@latest baseline.txt bench.txt`.
func Bench() error {
	mg.Deps(Plugins)
	out := envOr("BENCH_OUT", "bench.txt")
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()
	w := io.MultiWriter(os.Stdout, f)
	_, err = sh.Exec(nil, w, os.Stderr, "go", "test", "./...",
		"-run=^$",
		"-bench="+envOr("BENCH", "."),
		"-benchmem",
		"-count="+envOr("BENCH_COUNT", "10"),
		"-timeout=0",
	)
	if err == nil {
		fmt.Printf("results saved to %s\n", out)
	}
	return err
}

// envOr returns the value of the environment variable key, or def if it
// is unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Clean removes all compiled plugin .so files.
func Clean() error {
	matches, err := filepath.Glob(filepath.Join(pluginDir, "*.so"))
	if err != nil {
		return err
	}
	for _, f := range matches {
		fmt.Printf("removing %s\n", f)
		if err := os.Remove(f); err != nil {
			return err
		}
	}
	return nil
}
