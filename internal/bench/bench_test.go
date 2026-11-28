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

package bench

import (
	"math"
	"testing"
)

func TestPercentileNearestRank(t *testing.T) {
	sorted := []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}
	cases := []struct {
		p    float64
		want float64
	}{
		{50, 50},  // nearest-rank: ceil(0.5*10)-1 = 4 → 50
		{95, 100}, // ceil(9.5)-1 = 9 → 100
		{99, 100},
		{0, 10},
	}
	for _, c := range cases {
		if got := percentile(sorted, c.p); got != c.want {
			t.Errorf("percentile(%.0f) = %v, want %v", c.p, got, c.want)
		}
	}
	if !math.IsNaN(percentile(nil, 50)) {
		t.Errorf("percentile(nil) must be NaN")
	}
}

func resultsOf(version string, wl map[string]float64) *Results {
	r := &Results{BenchVersion: version}
	for name, p95 := range wl {
		r.Workloads = append(r.Workloads, WorkloadStat{Name: name, P95: p95})
	}
	return r
}

func TestComparePassAndRegress(t *testing.T) {
	base := resultsOf(BenchVersion, map[string]float64{"service_filter": 100})
	// +10%: pass at tolerance 1.2
	fresh := resultsOf(BenchVersion, map[string]float64{"service_filter": 110})
	rows, regressed := Compare(base, fresh, 1.2, MinAbsMsDefault)
	if regressed || len(rows) != 1 || rows[0].Regressed {
		t.Fatalf("+10%% must pass: %+v regressed=%v", rows, regressed)
	}
	// +50%: regress
	fresh = resultsOf(BenchVersion, map[string]float64{"service_filter": 150})
	rows, regressed = Compare(base, fresh, 1.2, MinAbsMsDefault)
	if !regressed || !rows[0].Regressed || rows[0].Ratio != 1.5 {
		t.Fatalf("+50%% must regress: %+v", rows)
	}
	// exact tolerance boundary (120 vs 100 × 1.2): not a regression
	fresh = resultsOf(BenchVersion, map[string]float64{"service_filter": 120})
	_, regressed = Compare(base, fresh, 1.2, MinAbsMsDefault)
	if regressed {
		t.Fatalf("boundary 1.2x must pass (strict >)")
	}
	// absolute noise floor: sub-ms jitter (0.6→0.8 ms = 1.33x) must NOT
	// fire the gate (real measured case on the 1M corpus)
	base2 := resultsOf(BenchVersion, map[string]float64{"point_lookup": 0.6})
	fresh2 := resultsOf(BenchVersion, map[string]float64{"point_lookup": 0.8})
	_, regressed = Compare(base2, fresh2, 1.2, MinAbsMsDefault)
	if regressed {
		t.Fatalf("sub-ms jitter must pass the noise floor")
	}
	// the floor is configurable: with floor 0, the same 1.33x jitter fires
	_, regressed = Compare(base2, fresh2, 1.2, 0)
	if !regressed {
		t.Fatalf("floor 0 must restore the ratio-only gate")
	}
	// real regression (250→500 ms) still fires both gates
	base3 := resultsOf(BenchVersion, map[string]float64{"service_filter": 250})
	fresh3 := resultsOf(BenchVersion, map[string]float64{"service_filter": 500})
	rows3, regressed := Compare(base3, fresh3, 1.2, MinAbsMsDefault)
	if !regressed || !rows3[0].Regressed {
		t.Fatalf("2x on a 250ms workload must regress")
	}
	// above ratio but under the floor (250→270, 1.08x… use 280: 1.12x) — pass
	fresh4 := resultsOf(BenchVersion, map[string]float64{"service_filter": 280})
	_, regressed = Compare(base3, fresh4, 1.2, MinAbsMsDefault)
	if regressed {
		t.Fatalf("280ms vs 250ms (1.12x) must pass")
	}
	// above ratio AND above floor (250→300: 1.2x not exceeded — use 310) — regress
	fresh5 := resultsOf(BenchVersion, map[string]float64{"service_filter": 310})
	_, regressed = Compare(base3, fresh5, 1.2, MinAbsMsDefault)
	if !regressed {
		t.Fatalf("310ms vs 250ms (1.24x, +60ms) must regress")
	}
}

func TestCompareFailsClosed(t *testing.T) {
	base := resultsOf(BenchVersion, map[string]float64{"service_filter": 100})
	// version mismatch → gate fails closed
	fresh := resultsOf("bench-vFUTURE", map[string]float64{"service_filter": 90})
	_, regressed := Compare(base, fresh, 1.2, MinAbsMsDefault)
	if !regressed {
		t.Fatalf("version mismatch must fail closed")
	}
	// missing workload → fail closed
	fresh = resultsOf(BenchVersion, map[string]float64{"service_filter": 90, "relations": 50})
	rows, regressed := Compare(base, fresh, 1.2, MinAbsMsDefault)
	if !regressed {
		t.Fatalf("missing baseline workload must fail closed")
	}
	found := false
	for _, r := range rows {
		if r.Workload == "relations" && r.Regressed {
			found = true
		}
	}
	if !found {
		t.Fatalf("relations row must be the regressed one: %+v", rows)
	}
}

func TestResultsRoundTrip(t *testing.T) {
	r := resultsOf(BenchVersion, map[string]float64{"a": 1.5})
	r.Probes = Probes{IP1: "10.0.0.1", ASN: 64512, Org: "ACME"}
	data, err := SaveResults(r)
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	back, err := LoadResults(data)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if back.BenchVersion != BenchVersion || back.Probes.IP1 != "10.0.0.1" || len(back.Workloads) != 1 {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
	if _, err := LoadResults([]byte(`{"nope":1}`)); err == nil {
		t.Fatalf("file without bench_version must be rejected")
	}
}
