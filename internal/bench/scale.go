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

// scale.go — v0.3.3 product-quality measurements (R5 of the master
// mandate): real import throughput, RAM/disk footprint, and search
// latency measured as the dataset grows 1x → 10x → 100x, plus labeled
// ground-truth accuracy through the production search service.
//
// HONESTY CONTRACT: the corpus is SYNTHETIC (deterministic generator,
// documentation-reserved namespaces: example hostnames, RFC 1918
// addresses, private ASNs).  Every scale row reports what actually
// happened on this machine through the REAL dataset import path (the
// same gzip payload, checksum verification, and atomic ingestion the
// channel update uses) — nothing is extrapolated.

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/dataset"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/searchlite"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// ScaleRow is one measured scale point.
type ScaleRow struct {
	Multiplier   int     `json:"multiplier"`
	Records      int     `json:"records"`
	Observations int64   `json:"observations_ingested"`
	Deduped      int64   `json:"observations_deduped"`
	WallSeconds  float64 `json:"import_wall_seconds"`
	RowsPerSec   float64 `json:"import_rows_per_second"`
	DBBytes      int64   `json:"db_bytes"`
	RSSBeforeKB  int64   `json:"rss_before_kb"`
	RSSAfterKB   int64   `json:"rss_after_kb"`
	RSSDeltaKB   int64   `json:"rss_delta_kb"`
	SearchP50Ms  float64 `json:"search_p50_ms"`
	SearchP95Ms  float64 `json:"search_p95_ms"`
}

// ScaleReport is the full 1x/10x/100x measurement.
type ScaleReport struct {
	Base      int        `json:"base_records"`
	Rows      []ScaleRow `json:"rows"`
	Generated time.Time  `json:"generated_at"`
	Notes     string     `json:"notes"`
}

// qualityRow is one labeled ground-truth query's accuracy.
type QualityRow struct {
	Query     string  `json:"query"`
	Mode      string  `json:"mode"`
	Expected  int     `json:"expected"`
	Returned  int     `json:"returned"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
}

// QualityReport is the labeled-accuracy result over the synthetic corpus.
type QualityReport struct {
	CorpusRecords int          `json:"corpus_records"`
	Queries       []QualityRow `json:"queries"`
	Accuracy      float64      `json:"accuracy"` // share of queries with F1 == 1.0
	Generated     time.Time    `json:"generated_at"`
	Notes         string       `json:"notes"`
}

// scaleCountries cycles deterministic (synthetic) country codes.
var scaleCountries = []string{"US", "DE", "ID", "SG", "JP", "BR"}

// scaleSources cycles the synthetic evidence sources (mirroring the real
// layer mix: CT, DNS, TLS).
var (
	scaleSources   = []string{"bench-ct", "bench-dns", "bench-tls"}
	scaleConnector = []string{"ct", "dns", "tls"}
	scalePorts     = []int{443, 80, 8080, 22, 8443, 25}
	scaleProto     = []string{"https", "http", "http", "ssh", "https", "smtp"}
)

// ScaleRecord returns the deterministic record i (shared by the payload
// generator and the ground-truth expectations).
func ScaleRecord(i int, now time.Time) dataset.Record {
	src := scaleSources[i%len(scaleSources)]
	obs := dataset.RecordObservation{
		Source:      src,
		Connector:   scaleConnector[i%len(scaleConnector)],
		ObservedAt:  now.Add(-time.Duration(i%86400) * time.Second),
		PayloadHash: scalePayloadHash(i),
		Provenance:  scaleConnector[i%len(scaleConnector)],
	}
	rec := dataset.Record{Schema: dataset.SchemaVersion, Observation: obs}
	switch i % 3 {
	case 0: // ip asset with one service — RFC 1918 addresses only
		ip := fmt.Sprintf("10.%d.%d.%d", (i/65536)%250+1, (i/254)%250+1, i%250+1)
		// The enrichment cycles index by i/3 (NOT i): services and
		// enrichment exist only on ip records (i%3==0), so an i-based
		// cycle would only ever reach the slices' first third.
		k := i / 3
		rec.Asset = dataset.RecordAsset{
			Kind:       "ip",
			Value:      ip,
			IP:         &ip,
			ASN:        65001 + k%40, // private ASN space (64512..65534)
			ASNOrg:     fmt.Sprintf("Bench Org %d", 65001+k%40),
			GeoCountry: scaleCountries[k%len(scaleCountries)],
		}
		rec.Service = &dataset.RecordService{
			Port:      scalePorts[k%len(scalePorts)],
			Transport: "tcp",
			Protocol:  scaleProto[k%len(scaleProto)],
			Name:      scaleProto[k%len(scaleProto)],
			Product:   "bench-server",
			Version:   "1.0",
		}
	case 1: // hostname — the reserved example TLD
		host := fmt.Sprintf("host%d.bench%d.example", i%997, i%7919)
		dom := fmt.Sprintf("bench%d.example", i%7919)
		rec.Asset = dataset.RecordAsset{Kind: "hostname", Value: host, Hostname: &host, Domain: &dom}
	default: // domain
		dom := fmt.Sprintf("bench%d.example", i%3001)
		rec.Asset = dataset.RecordAsset{Kind: "domain", Value: dom, Domain: &dom}
	}
	return rec
}

// scalePayloadHash is a stable per-record identity (the L2 hash the real
// collectors carry).
func scalePayloadHash(i int) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(fmt.Sprintf("bench-corpus:%d", i)))
	return strconv.FormatUint(h.Sum64(), 16)
}

// buildScalePayload writes n deterministic records as a gzipped NDJSON
// dataset payload and returns its path + manifest.
func buildScalePayload(dir string, n int, now time.Time, version int64) (string, *dataset.Manifest, error) {
	payloadPath := filepath.Join(dir, fmt.Sprintf("gseer-bench-v%d.ndjson.gz", version))
	f, err := os.Create(payloadPath)
	if err != nil {
		return "", nil, err
	}
	defer func() { _ = f.Close() }()
	gz := gzip.NewWriter(f)
	enc := json.NewEncoder(gz)
	var oldest, newest = now, now
	for i := 0; i < n; i++ {
		rec := ScaleRecord(i, now)
		if rec.Observation.ObservedAt.Before(oldest) {
			oldest = rec.Observation.ObservedAt
		}
		if rec.Observation.ObservedAt.After(newest) {
			newest = rec.Observation.ObservedAt
		}
		if err := enc.Encode(rec); err != nil {
			return "", nil, err
		}
	}
	if err := gz.Close(); err != nil {
		return "", nil, err
	}
	if err := f.Sync(); err != nil {
		return "", nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		return "", nil, err
	}
	_, _ = f.Seek(0, io.SeekStart)
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", nil, err
	}
	m := &dataset.Manifest{
		SchemaVersion:  dataset.SchemaVersion,
		DatasetVersion: version,
		GeneratedAtUTC: now.UTC(),
		Payload: dataset.PayloadInfo{
			Filename:  filepath.Base(payloadPath),
			SizeBytes: fi.Size(),
			SHA256:    hex.EncodeToString(h.Sum(nil)),
			Records:   int64(n),
		},
		Freshness: dataset.FreshnessInfo{OldestObservedAt: oldest.UTC(), NewestObservedAt: newest.UTC()},
		Notes:     "synthetic benchmark corpus — NOT real internet evidence",
	}
	return payloadPath, m, nil
}

// provisionBenchDB creates a fresh, migrated bench database (the same
// schema a personal setup provisions).
func provisionBenchDB(ctx context.Context, dbPath string) error {
	res, err := sqlite.Open(dbPath)
	if err != nil {
		return fmt.Errorf("provision the bench database: %w", err)
	}
	defer func() { _ = res.DB.Close() }()
	if _, err := sqlite.Migrate(ctx, res.DB); err != nil {
		return fmt.Errorf("migrate the bench database: %w", err)
	}
	return nil
}

// readRSSKB reads the current resident set from /proc (Linux); returns
// 0 when unavailable (non-Linux) — the report then simply omits RAM.
func readRSSKB() int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				if v, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					return v
				}
			}
		}
	}
	return 0
}

// probeSearchLatency runs a fixed point query `port==443` 20 times
// through the production search service and returns p50/p95 in ms.
func probeSearchLatency(ctx context.Context, db *sql.DB) (p50, p95 float64, err error) {
	svc := searchlite.New(db)
	var samples []float64
	for i := 0; i < 20; i++ {
		start := time.Now()
		res, err := svc.Search(ctx, search.Query{GQL: `port==443`, Mode: "service", Limit: 100})
		if err != nil {
			return 0, 0, err
		}
		if len(res.Rows) == 0 {
			return 0, 0, fmt.Errorf("probe query returned no rows at scale")
		}
		samples = append(samples, float64(time.Since(start).Microseconds())/1000.0)
	}
	sort.Float64s(samples)
	return percentile(samples, 50), percentile(samples, 95), nil
}

// Scale measures the real dataset-import path at each multiplier of the
// base corpus, in a fresh isolated database per point.
func Scale(ctx context.Context, base int, multipliers []int, dir string) (*ScaleReport, error) {
	now := time.Now().UTC().Truncate(time.Second)
	rep := &ScaleReport{Base: base, Generated: now,
		Notes: "synthetic corpus through the real dataset import path; RSS delta = incremental resident footprint (peaks include SQLite cache); search probes through the production service"}
	for _, mult := range multipliers {
		if mult <= 0 {
			continue
		}
		n := base * mult
		workDir, err := os.MkdirTemp(dir, "bench-scale-*")
		if err != nil {
			return nil, err
		}
		row := ScaleRow{Multiplier: mult, Records: n}

		payloadPath, manifest, err := buildScalePayload(workDir, n, now, int64(mult))
		if err != nil {
			return nil, fmt.Errorf("scale %dx: %w", mult, err)
		}

		dbPath := filepath.Join(workDir, "bench.db")
		if err := provisionBenchDB(ctx, dbPath); err != nil {
			return nil, fmt.Errorf("scale %dx: %w", mult, err)
		}

		rssBefore := readRSSKB()
		start := time.Now()
		res, err := dataset.Import(ctx, dataset.ImportOptions{
			DBPath:      dbPath,
			PayloadPath: payloadPath,
			Manifest:    manifest,
			ManifestURL: "file://synthetic-bench",
		})
		row.WallSeconds = time.Since(start).Seconds()
		rssAfter := readRSSKB()
		if err != nil {
			return nil, fmt.Errorf("scale %dx: import: %w", mult, err)
		}
		row.Observations = int64(res.Stats.ObservationsInserted)
		row.Deduped = int64(res.Stats.ObservationsDeduped)
		row.RowsPerSec = float64(n) / row.WallSeconds
		row.RSSBeforeKB, row.RSSAfterKB = rssBefore, rssAfter
		row.RSSDeltaKB = rssAfter - rssBefore
		if fi, serr := os.Stat(dbPath); serr == nil {
			row.DBBytes = fi.Size()
		}

		db, err := sql.Open("sqlite", dbPath)
		if err != nil {
			return nil, err
		}
		p50, p95, qerr := probeSearchLatency(ctx, db)
		_ = db.Close()
		if qerr != nil {
			return nil, fmt.Errorf("scale %dx: probe: %w", mult, qerr)
		}
		row.SearchP50Ms, row.SearchP95Ms = p50, p95
		rep.Rows = append(rep.Rows, row)
		_ = os.RemoveAll(workDir)
	}
	return rep, nil
}

// labeledQuery pairs a GQL query with its ground-truth predicate over
// the generated corpus (the generator IS the ground truth).
type labeledQuery struct {
	GQL  string
	Mode string
	Want func(rec dataset.Record) bool
	// Service mode compares (asset, port) pairs; asset mode compares
	// (kind, value) pairs.
	ByService bool
}

// qualityQueries are the labeled queries proving exact, prefix,
// cross-entity, CIDR, and combination capability on known data.
func qualityQueries() []labeledQuery {
	return []labeledQuery{
		{GQL: `port==443`, Mode: "service", ByService: true,
			Want: func(r dataset.Record) bool { return r.Service != nil && r.Service.Port == 443 }},
		{GQL: `port IN (80, 8080)`, Mode: "service", ByService: true,
			Want: func(r dataset.Record) bool {
				return r.Service != nil && (r.Service.Port == 80 || r.Service.Port == 8080)
			}},
		{GQL: `ip=="10.1.1.1"`, Mode: "asset",
			Want: func(r dataset.Record) bool { return r.Asset.Kind == "ip" && r.Asset.Value == "10.1.1.1" }},
		{GQL: `ip IN_CIDR "10.1.0.0/16"`, Mode: "asset",
			Want: func(r dataset.Record) bool { return r.Asset.Kind == "ip" && strings.HasPrefix(r.Asset.Value, "10.1.") }},
		{GQL: `asn==65001`, Mode: "asset",
			Want: func(r dataset.Record) bool { return r.Asset.Kind == "ip" && r.Asset.ASN == 65001 }},
		{GQL: `country=="DE"`, Mode: "asset",
			Want: func(r dataset.Record) bool { return r.Asset.Kind == "ip" && r.Asset.GeoCountry == "DE" }},
		{GQL: `org contains "Bench Org 650"`, Mode: "asset",
			Want: func(r dataset.Record) bool {
				return r.Asset.Kind == "ip" && strings.Contains(r.Asset.ASNOrg, "Bench Org 650")
			}},
		{GQL: `app=="bench-server"`, Mode: "service", ByService: true,
			Want: func(r dataset.Record) bool { return r.Service != nil && r.Service.Product == "bench-server" }},
		{GQL: `domain=="bench17.example"`, Mode: "asset",
			Want: func(r dataset.Record) bool { return r.Asset.Kind == "domain" && r.Asset.Value == "bench17.example" }},
		{GQL: `hostname *="host7.bench7.*"`, Mode: "asset",
			Want: func(r dataset.Record) bool {
				return r.Asset.Kind == "hostname" && strings.HasPrefix(r.Asset.Value, "host7.bench7.")
			}},
	}
}

// Quality imports a synthetic corpus through the REAL dataset import
// path, then answers every labeled query through the production search
// service and scores precision/recall/F1 against the generator's
// expected sets.
func Quality(ctx context.Context, records int, dir string) (*QualityReport, error) {
	now := time.Now().UTC().Truncate(time.Second)
	workDir, err := os.MkdirTemp(dir, "bench-quality-*")
	if err != nil {
		return nil, err
	}
	payloadPath, manifest, err := buildScalePayload(workDir, records, now, 1)
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(workDir, "quality.db")
	if err := provisionBenchDB(ctx, dbPath); err != nil {
		return nil, err
	}
	if _, err := dataset.Import(ctx, dataset.ImportOptions{
		DBPath:      dbPath,
		PayloadPath: payloadPath,
		Manifest:    manifest,
		ManifestURL: "file://synthetic-quality",
	}); err != nil {
		return nil, fmt.Errorf("quality: import: %w", err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = db.Close() }()
	svc := searchlite.New(db)

	// The ground truth: walk the generator, bucket the expected keys per
	// query.  Service mode matches (asset, port) pairs; asset mode
	// matches (kind, value) pairs.
	expected := make([]map[string]bool, len(qualityQueries()))
	for i := range expected {
		expected[i] = map[string]bool{}
	}
	for i := 0; i < records; i++ {
		rec := ScaleRecord(i, now)
		for qi, q := range qualityQueries() {
			if !q.Want(rec) {
				continue
			}
			if q.ByService {
				expected[qi][rec.Asset.Value+"\x00"+strconv.Itoa(rec.Service.Port)] = true
			} else {
				expected[qi][rec.Asset.Kind+"\x00"+rec.Asset.Value] = true
			}
		}
	}

	rep := &QualityReport{CorpusRecords: records, Generated: now,
		Notes: "ground truth = the deterministic generator itself; queries answered through the production search service"}
	for qi, q := range qualityQueries() {
		row := QualityRow{Query: q.GQL, Mode: q.Mode}
		// Page through the full result set (limit 0 = server default;
		// the corpus slices are small enough for a high limit).
		got := map[string]bool{}
		cursor := ""
		for page := 0; page < 200; page++ {
			res, err := svc.Search(ctx, search.Query{GQL: q.GQL, Mode: q.Mode, Limit: 1000, Cursor: cursor})
			if err != nil {
				return nil, fmt.Errorf("quality query %q: %w", q.GQL, err)
			}
			for _, r := range res.Rows {
				if q.ByService && r.Port != nil {
					got[r.AssetValue+"\x00"+strconv.Itoa(*r.Port)] = true
				} else if !q.ByService {
					got[r.AssetKind+"\x00"+r.AssetValue] = true
				}
			}
			if !res.HasMore || res.NextCursor == "" {
				break
			}
			cursor = res.NextCursor
		}
		row.Expected = len(expected[qi])
		row.Returned = len(got)
		precision := 1.0
		if row.Returned > 0 {
			hit := 0
			for k := range got {
				if expected[qi][k] {
					hit++
				}
			}
			precision = float64(hit) / float64(row.Returned)
		}
		recall := 0.0
		if row.Expected > 0 {
			hit := 0
			for k := range expected[qi] {
				if got[k] {
					hit++
				}
			}
			recall = float64(hit) / float64(row.Expected)
		}
		row.Precision = precision
		row.Recall = recall
		row.F1 = 0
		if precision+recall > 0 {
			row.F1 = 2 * precision * recall / (precision + recall)
		}
		rep.Queries = append(rep.Queries, row)
	}
	perfect := 0
	for _, q := range rep.Queries {
		if q.F1 == 1.0 {
			perfect++
		}
	}
	rep.Accuracy = float64(perfect) / float64(len(rep.Queries))
	_ = os.RemoveAll(workDir)
	return rep, nil
}
