# GSEER benchmarking (R140)

**bench-v3** (r23): `hostname_prefix` now uses the real wildcard
operator (`*=`, OpMatch — the v2 `==`-with-star form matched nothing,
caught in R114 review) and adds `tls_filter` + `ct_filter` workloads —
benchgen now generates TLS and CT evidence through the same generic
projection the collectors use.  Probes are discovered from the corpus;
workloads skip honestly when the corpus has no such data.  v2
baselines fail closed — re-baseline after upgrading.  The R114
relevance default applies to eligible bench queries (narrow prefix
sets rank; corpus-scale sets take the measured fallback path).

**bench-v2** (r21): adds the `hostname_prefix` workload and fails closed
against v1 baselines (version mismatch = REGRESSION, exit 6) — re-run
`make bench-baseline` after upgrading.  v2 exists because migration 0015
changed the hostname-prefix path's measured performance shape
(SCAN assets ~95 ms → index-served ~0 ms on the 1M corpus).

`gseer bench` measures the SAME search pipeline users get — the fixed
workload set runs through the production search service (`searchlite`),
never a special path. Search never triggers scanning; the harness is
strictly read-only.

## Workloads (bench-v1)
| workload       | queries (fixed GQL)                          | intent                        |
|----------------|----------------------------------------------|-------------------------------|
| point_lookup   | `ip == "<probe1>"`, `ip == "<probe2>"`       | exact-asset lookup latency    |
| service_filter | `port == 443 && protocol == "https"`, `port == 80`, `port == 22` | common filter scans |
| asn_filter     | `asn == <probe>`, `asn_org == "<probe>"`     | network attribution queries   |
| facets         | `port == 443` + facets(port, protocol)       | aggregation cost              |
| relations      | relations.Explore(probe IP)                  | evidence-graph traversal      |
| hostname_prefix| `hostname *= "<label>*"` (wildcard prefix, index-served), `hostname *= "*.<domain>"` (substring scan — honest baseline) | subdomain/hostname search; SKIPPED when the corpus has no hostnames |
| tls_filter     | `tls.version == "<discovered>"`, `tls.cert_issuer_cn CONTAINS "<word>"` | TLS-certificate search; SKIPPED when the corpus has no TLS evidence |
| ct_filter      | `ct.entry_type == "<discovered>"`, `ct.issuer CONTAINS "<word>"`  | Certificate-Transparency search; SKIPPED when the corpus has no CT evidence |

Probe inputs are discovered deterministically from the index (ORDER BY id)
and RECORDED in the results file — compare always shows what it measured.
Requires a populated index (bench on an empty index errors honestly).

## Measurement
- 1 warmup + N measured runs per query (default N=5, `--runs`).
- Percentiles per workload: p50/p95/p99/max (nearest-rank).
- A failing measured run records the 10 s query timeout — honest, and it
  will trip the gate.

## Regression gate
`gseer bench compare` gates a fresh run (`bench/last.json` or `--file`)
against the baseline (`bench/baseline.json`, written by `bench run --save`):

    regressed  ⇔  p95_new > p95_base × tolerance   AND   p95_new − p95_base > min-abs-ms

Defaults: tolerance 1.2 (+20%), min-abs-ms 25. The absolute floor exists
because of MEASURED reality (1M corpus): real workloads reproduce within
2% run-to-run, but sub-millisecond point lookups jitter >40% — a
ratio-only gate would false-fire on 0.6→0.8 ms. Both knobs are flags.
Fail-closed: a missing workload or a bench-version mismatch is a REGRESSION.
A regression exits with code 6 (`ExitBenchRegress`) so CI can block it.

## Baseline on the verified 1M-asset / 1.0 GiB corpus (r21, bench-v2)
point_lookup p50 0.5 ms · service_filter p95 245 ms · asn_filter p95
279 ms · facets p95 333 ms · relations p95 242 ms · hostname_prefix p95
240 ms (narrow wildcard-prefix half is index-served at ~0 ms; the
p95 is dominated by the honest substring-suffix half).

## Make integration (release gate)
    make bench-corpus     # reproducible benchgen corpus at $(HOME)/.gseer-bench (BENCH_ASSETS, default 200k)
    make bench-baseline   # measure + save baseline (one-time per corpus)
    make bench-check      # fresh run + gate; REGRESSION = exit 6; no baseline = exit 2 (fail-closed)
    make release-validate # build + vet + test + bench-check — the gate cannot be silently skipped

Dev knobs (make variables): BENCH_HOME, BENCH_ASSETS, BENCH_RUNS,
BENCH_TOLERANCE, BENCH_MIN_ABS_MS.  The documented 1M baseline above uses
BENCH_ASSETS=1000000.  A >20% corpus-size difference between baseline and
fresh run is a clear E_BENCH error (exit 2), never a false regression.

## Skala & kualitas produk (v0.3.3)

Dua pengukuran baru melengkapi `bench run`/`bench compare`:

- **`gseer bench scale [--base 343] [--times 1,10,100]`** — membangun
  korpus sintetis deterministik (namespace `example`, RFC 1918, ASN
  privat), lalu mengukur jalur import dataset NYATA (payload gzip +
  checksum + import atomik yang sama dengan channel) pada setiap
  pengali: wall time, rows/detik, ukuran DB, delta RSS, dan latensi
  search `port==443` (p50/p95) melalui service produksi.  Setiap titik
  berjalan di database terisolasi dan dihapus setelah diukur.
- **`gseer bench quality [--corpus 3000]`** — generator korpus ADALAH
  ground truth: 10 query berlabel (exact, IN, CIDR, prefix, kombinasi
  operator, entity) dijawab melalui service search produksi, lalu
  dibandingkan dengan himpunan yang diharapkan per kueri
  (precision/recall/F1).  `accuracy` = porsi query dengan F1 == 1.0;
  F1 < 1 pada kueri mana pun adalah regresi engine, bukan noise data.

Kejujuran: angka throughput/latensi adalah pengukuran nyata di mesin
Anda; ISI korpusnya sintetis (lihat KNOWN-LIMITATIONS.md §10).
