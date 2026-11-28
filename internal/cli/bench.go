// GSEER — internet-asset search engine.
// Copyright (C) 2026  The GSEER Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cli

// bench.go — `gseer bench` (R140): reproducible performance measurement
// and a regression gate.  run  = measure the fixed workload set through
// the production search service;  compare = gate a fresh run against a
// saved baseline (p95 × tolerance; fail-closed) with exit code
// ExitBenchRegress so CI can block perf regressions.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/bench"
	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

var (
	fBenchRuns      int
	fBenchSave      bool
	fBenchJSON      bool
	fBenchFile      string
	fBenchTolerance float64
	fBenchMinAbs    float64

	fBenchScaleTimes    string
	fBenchScaleBase     int
	fBenchScaleDir      string
	fBenchQualityCorpus int
)

func registerBenchCmd(root *cobra.Command) {
	benchCmd := &cobra.Command{
		Use:   "bench",
		Short: "Reproducible performance benchmarks and regression gating (R140)",
		Args:  cobra.NoArgs,
	}
	run := &cobra.Command{
		Use:   "run",
		Short: "Measure the fixed workload set against the current index",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			if cfg.Profile != config.ProfilePersonal {
				printf(out, "E_PROFILE_UNSUPPORTED: gseer bench is verified on the personal (SQLite) store in this release\n"+
					"Why: the self-hosted PostgreSQL green path is still sandbox-blocked (see R61-PG-PARITY-EVIDENCE.md)\n")
				exitWith(ExitConfig)
				return nil
			}
			return runBench(out, cfg, fBenchRuns, fBenchSave, fBenchJSON)
		},
	}
	run.Flags().IntVar(&fBenchRuns, "runs", 5, "measured runs per query (1 warmup excluded)")
	run.Flags().BoolVar(&fBenchSave, "save", false, "save the result as the baseline (GSEER_HOME/bench/baseline.json)")
	run.Flags().BoolVar(&fBenchJSON, "json", false, "machine-readable output")

	cmp := &cobra.Command{
		Use:   "compare",
		Short: "Gate a fresh run against a baseline (exit 6 on regression)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			if cfg.Profile != config.ProfilePersonal {
				printf(out, "E_PROFILE_UNSUPPORTED: gseer bench is verified on the personal (SQLite) store in this release\n")
				exitWith(ExitConfig)
				return nil
			}
			return runBenchCompare(out, cfg, fBenchFile, fBenchTolerance, fBenchJSON)
		},
	}
	cmp.Flags().StringVar(&fBenchFile, "file", "", "fresh-run results file (default: <GSEER_HOME>/bench/last.json)")
	cmp.Flags().Float64Var(&fBenchTolerance, "tolerance", 1.2, "allowed p95 ratio vs baseline (1.2 = +20%)")
	cmp.Flags().Float64Var(&fBenchMinAbs, "min-abs-ms", bench.MinAbsMsDefault, "absolute p95 noise floor (ms); a workload must exceed BOTH gates")
	cmp.Flags().BoolVar(&fBenchJSON, "json", false, "machine-readable output")

	scale := &cobra.Command{
		Use:   "scale",
		Short: "Measure the real dataset-import path and search latency at 1x/10x/100x corpus scale",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			defer cancel()
			var mults []int
			for _, part := range strings.Split(fBenchScaleTimes, ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				n, err := strconv.Atoi(part)
				if err != nil || n <= 0 {
					printf(out, "E_INVALID: --times must be comma-separated positive integers (got %q)\n", part)
					exitWith(ExitInvalidInput)
					return nil
				}
				mults = append(mults, n)
			}
			if len(mults) == 0 {
				mults = []int{1, 10, 100}
			}
			dir := fBenchScaleDir
			if dir == "" {
				dir = os.TempDir()
			}
			rep, err := bench.Scale(ctx, fBenchScaleBase, mults, dir)
			if err != nil {
				printf(out, "E_BENCH: %s\n", err.Error())
				exitWith(ExitInvalidInput)
				return nil
			}
			if fBenchJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			printf(out, "GSEER scale benchmark — synthetic corpus through the REAL dataset import path (nothing extrapolated)\n")
			printf(out, "  %-8s %10s %10s %12s %10s %9s %9s\n", "scale", "records", "ingested", "import (s)", "rows/s", "db (MiB)", "RSS+ (MiB)")
			for _, r := range rep.Rows {
				printf(out, "  %-8d %10d %10d %12.2f %10.0f %9.1f %9.1f\n",
					r.Multiplier, r.Records, r.Observations, r.WallSeconds, r.RowsPerSec,
					float64(r.DBBytes)/(1024*1024), float64(r.RSSDeltaKB)/1024)
			}
			printf(out, "  %-8s %10s %10s\n", "scale", "p50 (ms)", "p95 (ms)")
			for _, r := range rep.Rows {
				printf(out, "  port==443 @%-4d %10.1f %10.1f\n", r.Multiplier, r.SearchP50Ms, r.SearchP95Ms)
			}
			printf(out, "Honesty: synthetic corpus (RFC 1918 / example namespaces); RSS delta is the incremental resident footprint, peaks include the SQLite cache.\n")
			return nil
		},
	}
	scale.Flags().StringVar(&fBenchScaleTimes, "times", "1,10,100", "comma-separated scale multipliers (base × N records per point)")
	scale.Flags().IntVar(&fBenchScaleBase, "base", 343, "base corpus size in records (the 1x point)")
	scale.Flags().StringVar(&fBenchScaleDir, "workdir", "", "directory for the isolated bench databases (default: the OS temp dir)")

	quality := &cobra.Command{
		Use:   "quality",
		Short: "Score the search engine against labeled ground truth (precision/recall/F1 per query)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			dir := fBenchScaleDir
			if dir == "" {
				dir = os.TempDir()
			}
			rep, err := bench.Quality(ctx, fBenchQualityCorpus, dir)
			if err != nil {
				printf(out, "E_BENCH: %s\n", err.Error())
				exitWith(ExitInvalidInput)
				return nil
			}
			if fBenchJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			}
			printf(out, "GSEER quality benchmark — labeled ground truth (the deterministic generator IS the truth), production search service\n")
			printf(out, "  %-38s %8s %8s %10s %10s %10s\n", "query", "mode", "expected", "returned", "precision", "recall")
			for _, q := range rep.Queries {
				printf(out, "  %-38s %8s %8d %10d %10.3f %10.3f\n",
					q.Query, q.Mode, q.Expected, q.Returned, q.Precision, q.Recall)
			}
			printf(out, "accuracy (queries with F1 == 1.0): %.3f (%d/%d)\n",
				rep.Accuracy, func() int {
					n := 0
					for _, q := range rep.Queries {
						if q.F1 == 1.0 {
							n++
						}
					}
					return n
				}(), len(rep.Queries))
			return nil
		},
	}
	quality.Flags().IntVar(&fBenchQualityCorpus, "corpus", 3000, "synthetic corpus size in records")
	quality.Flags().StringVar(&fBenchScaleDir, "workdir", "", "directory for the isolated bench databases (default: the OS temp dir)")

	benchCmd.AddCommand(run, cmp, scale, quality)
	root.AddCommand(benchCmd)
}

// benchBaselinePath is where --save writes the baseline and where
// compare reads it from.
func benchBaselinePath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Database.DSN), "bench", "baseline.json")
}

func benchLastPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Database.DSN), "bench", "last.json")
}

// runBench executes the workload set, prints the table, always persists
// last.json (compare's default fresh-run source), and optionally the
// baseline.  Every query runs through the production search service.
func runBench(out io.Writer, cfg *config.Config, runs int, save, asJSON bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res, err := openPersonal(cfg)
	if err != nil {
		printf(out, "E_DB_UNAVAILABLE: %s\n", err.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	defer func() { _ = res.DB.Close() }()
	// R48 hardening (same as every personal command): migrate to head
	// before measuring — bench must report the CURRENT schema's
	// performance shape, never silently benchmark an old one.
	if _, mErr := sqlite.Migrate(ctx, res.DB); mErr != nil {
		printf(out, "E_DB_UNAVAILABLE: migrate: %s\n", mErr.Error())
		exitWith(ExitUnavailable)
		return nil
	}
	svc := searchlite.New(res.DB)

	results, samples, err := bench.Run(ctx, res.DB, svc, runs)
	if err != nil {
		printf(out, "E_BENCH: %s\n", err.Error())
		exitWith(ExitInvalidInput)
		return nil
	}

	// Persist last.json (and optionally the baseline) next to the index.
	dir := filepath.Dir(benchLastPath(cfg))
	if mkErr := os.MkdirAll(dir, 0o700); mkErr == nil {
		if data, sErr := bench.SaveResults(results); sErr == nil {
			_ = os.WriteFile(benchLastPath(cfg), data, 0o600)
			if save {
				_ = os.WriteFile(benchBaselinePath(cfg), data, 0o600)
			}
		}
	}

	if asJSON {
		data, _ := bench.SaveResults(results)
		_, _ = out.Write(data)
		_, _ = out.Write([]byte("\n"))
		return nil
	}

	printf(out, "GSEER benchmark — %s — %d run(s)/query (1 warmup excluded), production search service\n",
		bench.BenchVersion, results.Runs)
	printf(out, "Corpus: %d assets, %.1f MiB — probes: ip=%s ip2=%s asn=%d org=%q\n",
		results.AssetCount, float64(results.DBBytes)/(1024*1024),
		results.Probes.IP1, results.Probes.IP2, results.Probes.ASN, results.Probes.Org)
	printf(out, "  %-16s %10s %10s %10s %10s\n", "workload", "p50 (ms)", "p95 (ms)", "p99 (ms)", "max (ms)")
	for _, w := range results.Workloads {
		printf(out, "  %-16s %10.1f %10.1f %10.1f %10.1f\n", w.Name, w.P50, w.P95, w.P99, w.Max)
	}
	printf(out, "\nPer-query samples: %d (recorded in last.json)\n", len(samples))
	if save {
		printf(out, "Baseline saved: %s\n", benchBaselinePath(cfg))
	} else {
		printf(out, "Gate this run: gseer bench compare [--file %s]\n", benchLastPath(cfg))
	}
	return nil
}

// runBenchCompare loads the fresh run + baseline and applies the p95 ×
// tolerance gate (fail-closed on missing workloads / version mismatch).
func runBenchCompare(out io.Writer, cfg *config.Config, file string, tolerance float64, asJSON bool) error {
	freshPath := file
	if freshPath == "" {
		freshPath = benchLastPath(cfg)
	}
	data, err := os.ReadFile(freshPath)
	if err != nil {
		printf(out, "E_BENCH: no fresh-run results at %s — run `gseer bench run` first\n", freshPath)
		exitWith(ExitInvalidInput)
		return nil
	}
	fresh, err := bench.LoadResults(data)
	if err != nil {
		printf(out, "E_BENCH: %s is not a bench results file: %s\n", freshPath, err.Error())
		exitWith(ExitInvalidInput)
		return nil
	}
	basePath := benchBaselinePath(cfg)
	baseData, err := os.ReadFile(basePath)
	if err != nil {
		printf(out, "E_BENCH: no baseline at %s — save one with `gseer bench run --save`\n", basePath)
		exitWith(ExitInvalidInput)
		return nil
	}
	base, err := bench.LoadResults(baseData)
	if err != nil {
		printf(out, "E_BENCH: baseline unreadable: %s\n", err.Error())
		exitWith(ExitInvalidInput)
		return nil
	}

	// Corpus guard: comparing runs against different corpus sizes would
	// produce meaningless (often false-positive) verdicts.  Fail with a
	// clear error (rc 2) instead of a regression verdict (rc 6).
	if base.AssetCount > 0 && fresh.AssetCount > 0 {
		d := fresh.AssetCount - base.AssetCount
		if d < 0 {
			d = -d
		}
		if float64(d)/float64(base.AssetCount) > 0.2 {
			printf(out, "E_BENCH: corpus mismatch — baseline %d assets vs fresh %d assets (>20%% difference).\n"+
				"Why: the two runs measured different corpora, so the verdict would be meaningless.\n"+
				"Next: regenerate the baseline on the same corpus (make bench-baseline).\n", base.AssetCount, fresh.AssetCount)
			exitWith(ExitInvalidInput)
			return nil
		}
	}

	rows, regressed := bench.Compare(base, fresh, tolerance, fBenchMinAbs)
	if asJSON {
		printf(out, "{\"bench_version\":%q,\"regressed\":%t,\"rows\":[", fresh.BenchVersion, regressed)
		for i, r := range rows {
			if i > 0 {
				_, _ = out.Write([]byte(","))
			}
			ratio := "null"
			if !strings.Contains(fmt.Sprint(r.Ratio), "Inf") {
				ratio = fmt.Sprintf("%.3f", r.Ratio)
			}
			printf(out, "{\"workload\":%q,\"baseline_p95_ms\":%.3f,\"new_p95_ms\":%.3f,\"ratio\":%s,\"regressed\":%t}",
				r.Workload, r.BaseP95, r.NewP95, ratio, r.Regressed)
		}
		_, _ = out.Write([]byte("]}\n"))
	} else {
		printf(out, "Performance gate — fresh %s vs baseline %s (tolerance %.2fx p95, noise floor %.0f ms)\n",
			fresh.CreatedAt.Format(time.RFC3339), base.CreatedAt.Format(time.RFC3339), tolerance, bench.MinAbsMsDefault)
		printf(out, "  %-16s %12s %12s %8s  %s\n", "workload", "base p95", "new p95", "ratio", "verdict")
		for _, r := range rows {
			verdict := "PASS"
			if r.Regressed {
				verdict = "REGRESSED"
			}
			baseCell := "—"
			ratioCell := "—"
			if r.BaseP95 >= 0 {
				baseCell = fmt.Sprintf("%.1f ms", r.BaseP95)
				ratioCell = fmt.Sprintf("%.2fx", r.Ratio)
			}
			printf(out, "  %-16s %12s %12s %8s  %s\n", r.Workload, baseCell, fmt.Sprintf("%.1f ms", r.NewP95), ratioCell, verdict)
		}
	}
	if regressed {
		printf(out, "\nPERFORMANCE REGRESSION detected — the gate blocks this change (exit code 6).\n")
		exitWith(ExitBenchRegress)
		return nil
	}
	printf(out, "\nNo regression: every workload is within the gate.\n")
	return nil
}
