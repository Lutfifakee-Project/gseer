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

// benchgen — R44 benchmark corpus generator.
//
// Builds a deterministic personal-mode SQLite index through the REAL
// ingestion path (Store.IngestFacts, dedup included) so performance
// measurements reflect production writes, not hand-crafted SQL.  The
// corpus is fully deterministic (fixed seed via value hashing) so the
// R44/R49 benchmarks are reproducible by anyone with the source kit:
//
//	go run ./internal/bench/benchgen -db /tmp/r44bench/home/gseer.db \
//	    -assets 1000000 -svc 0.35 -obs 2 -batch 2000
//
// This is a development/measurement tool; it is NOT wired into any
// product command and never touches the network.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func main() {
	dbPath := flag.String("db", "", "path to gseer.db (created)")
	assetsN := flag.Int("assets", 100000, "number of assets")
	svcFrac := flag.Float64("svc", 0.35, "fraction of assets that get a service")
	obsPer := flag.Int("obs", 2, "observations per service")
	batch := flag.Int("batch", 2000, "facts per IngestFacts batch")
	flag.Parse()

	if *dbPath == "" {
		fmt.Fprintln(os.Stderr, "usage: benchgen -db <path> [-assets N] [-svc F] [-obs N] [-batch N]")
		os.Exit(2)
	}
	if err := os.MkdirAll(filepath.Dir(*dbPath), 0o755); err != nil {
		panic(err)
	}
	res, err := sqlite.Open(*dbPath)
	if err != nil {
		panic(err)
	}
	fmt.Printf("db=%s mode=%s\n", *dbPath, res.Mode)
	if _, err := sqlite.Migrate(context.Background(), res.DB); err != nil {
		panic(err)
	}
	st := sqlite.NewStore(res.DB)
	ctx := context.Background()

	srcID, err := st.EnsureFixtureSource(ctx)
	if err != nil {
		panic(err)
	}

	base := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	ports := []int{80, 443, 8080, 8443, 22, 53, 25, 3306, 6379, 9200}
	protos := []string{"http", "https", "ssh", "dns", "smtp", "mysql", "redis"}
	prods := []string{"nginx", "Apache httpd", "OpenSSH", "Microsoft-IIS/10", "cloudflare", "caddy"}
	titles := []string{"Welcome to nginx!", "Index of /", "Login", "Not Found", "Dashboard"}

	batchFacts := make([]storage.Fact, 0, *batch)
	var tIngest time.Duration
	var factsTotal int
	start := time.Now()

	flush := func() error {
		if len(batchFacts) == 0 {
			return nil
		}
		t0 := time.Now()
		stats, err := st.IngestFacts(ctx, batchFacts)
		tIngest += time.Since(t0)
		if err != nil {
			return err
		}
		factsTotal += len(batchFacts)
		if factsTotal%(*batch*20) == 0 {
			fmt.Printf("  %d facts: assets+=%d svc+=%d obs+=%d dedup=%d elapsed=%s\n",
				factsTotal, stats.AssetsInserted, stats.ServicesInserted, stats.ObservationsInserted, stats.ObservationsDeduped,
				time.Since(start).Round(time.Second))
		}
		batchFacts = batchFacts[:0]
		return nil
	}

	for i := 0; i < *assetsN; i++ {
		var f storage.Fact
		switch i % 10 {
		case 0, 1, 2, 3, 4, 5: // 60% IPs
			ip := fmt.Sprintf("%d.%d.%d.%d", 1+(i/16384)%223, (i/256)%256, i%256, (i*7)%254+1)
			f = ipFact("ip", ip, base.Add(time.Duration(i%86400)*time.Second))
			if i%100 < int(*svcFrac*100) {
				// give this asset a service + observations
				f.Service = &storage.Service{
					Port:      ports[i%len(ports)],
					Transport: "tcp",
					Protocol:  protos[i%len(protos)],
					Name:      protos[i%len(protos)],
					Product:   prods[i%len(prods)],
					Version:   fmt.Sprintf("1.%d.0", i%25),
				}
				f.Service.FirstSeen = f.Asset.FirstSeen
				f.Service.LastSeen = f.Asset.LastSeen
			}
		case 6, 7: // 20% domains
			f = assetFact("domain", fmt.Sprintf("example%d-%s.example", i, word(i)), base.Add(time.Duration(i%86400)*time.Second))
		default: // 20% hostnames
			f = assetFact("hostname", fmt.Sprintf("host%d.%s.example", i, word(i)), base.Add(time.Duration(i%86400)*time.Second))
		}
		if f.Service != nil {
			f.Observation.SourceID = srcID
			f.Observation.ObservedAt = f.Asset.LastSeen
			h := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d", f.Asset.Value, f.Service.Port, f.Observation.ObservedAt.Unix())))
			f.Observation.PayloadHash = hex.EncodeToString(h[:])
			f.Observation.Provenance = "fixture"
			f.Observation.SourceCursor = fmt.Sprintf("bench:%d", i)
			ev := map[string]any{}
			p := f.Service.Protocol
			switch p {
			case "http", "https":
				if p == "https" {
					// TLS evidence through the SAME generic projection
					// the collectors use (latest_tls_t -> search_index
					// tls.* columns).  Deterministic per-asset values.
					ev["tls"] = map[string]any{
						"version":         []string{"TLSv1.2", "TLSv1.3"}[i%2],
						"cert_subject_cn": fmt.Sprintf("%s.example", hostLabel(i)),
						"cert_issuer_cn":  "Bench CA",
						"cert_issuer_org": "Bench CA Authority",
						"cert_serial":     fmt.Sprintf("%032x", i),
						"cert_sans_dns":   []string{fmt.Sprintf("%s.example", hostLabel(i))},
						"cert_not_before": base.Add(-time.Duration(30+i%60) * 24 * time.Hour).Format(time.RFC3339),
						"cert_expiry":     base.Add(time.Duration(30+i%90) * 24 * time.Hour).Format(time.RFC3339),
					}
				}
				ev["http"] = map[string]any{
					"status": 200 + i%2,
					"title":  titles[i%len(titles)],
					"server": prods[i%len(prods)],
					"headers": map[string]string{
						"server":       prods[i%len(prods)],
						"x-powered-by": "Bench/1.0",
						"content-type": "text/html",
					},
				}
				ev["fingerprint"] = map[string]any{"technologies": []string{prods[i%len(prods)], "Bench"}}
			case "ssh":
				ev["banner"] = "SSH-2.0-OpenSSH_8.4"
			case "dns":
				ev["banner"] = "dnsmasq-2.89"
			default:
				ev["banner"] = "bench-banner"
			}
			f.Observation.Evidence = ev
			// obsPer observations per service (each a distinct payload)
			for k := 0; k < *obsPer; k++ {
				g := f
				g.Observation = f.Observation
				g.Observation.ObservedAt = f.Observation.ObservedAt.Add(time.Duration(k) * time.Minute)
				h2 := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%d", f.Asset.Value, f.Service.Port, g.Observation.ObservedAt.Unix(), k)))
				g.Observation.PayloadHash = hex.EncodeToString(h2[:])
				g.Observation.SourceCursor = fmt.Sprintf("bench:%d:%d", i, k)
				g.Observation.ID = benchBookkeepingID(g.Observation.SourceCursor)
				batchFacts = append(batchFacts, g)
			}
			continue
		}
		f.Observation.SourceID = srcID
		f.Observation.ObservedAt = f.Asset.LastSeen
		h := sha256.Sum256([]byte(f.Asset.Value + "|" + f.Observation.ObservedAt.Format(time.RFC3339)))
		f.Observation.PayloadHash = hex.EncodeToString(h[:])
		f.Observation.Provenance = "fixture"
		f.Observation.SourceCursor = fmt.Sprintf("bench:%d", i)
		f.Observation.Evidence = map[string]any{"seen": "true"}
		f.Observation.ID = benchBookkeepingID(f.Observation.SourceCursor)
		batchFacts = append(batchFacts, f)
		if i%3 == 0 {
			// CT log sighting — an ASSET-level observation (no service
			// row): the same evidence.ctlog shape the latest_ctlog_t
			// projection reads (search_index ct.* columns).
			c := f
			c.Service = nil
			c.Observation.SourceCursor = fmt.Sprintf("bench:ct:%d", i)
			h2 := sha256.Sum256([]byte("ct|" + f.Asset.Value))
			c.Observation.PayloadHash = hex.EncodeToString(h2[:])
			c.Observation.Evidence = map[string]any{
				"ctlog": map[string]any{
					"log":            "https://ct.bench.example/log1",
					"entry_type":     []string{"leaf", "precertificate"}[i%2],
					"subject_cn":     fmt.Sprintf("%s.example", hostLabel(i)),
					"issuer":         "Bench CA",
					"not_before":     base.Add(-time.Duration(60+i%120) * 24 * time.Hour).Format(time.RFC3339),
					"not_after":      base.Add(time.Duration(60+i%300) * 24 * time.Hour).Format(time.RFC3339),
					"leaf_sha256":    fmt.Sprintf("%064x", i),
					"cert_timestamp": base.Add(-time.Duration(i%720) * time.Hour).Format(time.RFC3339),
				},
			}
			c.Observation.ID = benchBookkeepingID(c.Observation.SourceCursor)
			batchFacts = append(batchFacts, c)
		}
		if err := flush(); err != nil {
			panic(err)
		}
	}
	if err := flush(); err != nil {
		panic(err)
	}
	d := time.Since(start)
	fmt.Printf("DONE facts=%d total=%s ingest=%s (%.0f facts/s)\n",
		factsTotal, d.Round(time.Second), tIngest.Round(time.Second), float64(factsTotal)/tIngest.Seconds())
}

// hostLabel derives the deterministic hostname-ish label used in TLS
// certificate subjects and CT entries for asset i.
func hostLabel(i int) string {
	return fmt.Sprintf("host%d.%s", i, word(i))
}

func ipFact(kind storage.AssetKind, value string, last time.Time) storage.Fact {
	return storage.Fact{
		Asset: storage.Asset{
			Kind: kind, Value: value,
			IP:         &value,
			ASN:        65000 + hashMod(value, 5000),
			ASNOrg:     fmt.Sprintf("Bench AS %d, LLC", 65000+hashMod(value, 5000)),
			GeoCountry: []string{"US", "DE", "SG", "BR", "ID", "JP", "NL"}[hashMod(value, 7)],
			Sources:    []string{"bench"},
			FirstSeen:  last.Add(-24 * time.Hour),
			LastSeen:   last,
		},
	}
}

func assetFact(kind storage.AssetKind, value string, last time.Time) storage.Fact {
	a := storage.Asset{
		Kind: kind, Value: value,
		Sources:   []string{"bench"},
		FirstSeen: last.Add(-24 * time.Hour),
		LastSeen:  last,
	}
	switch kind {
	case "domain":
		a.Domain = &value
	case "hostname":
		a.Hostname = &value
	}
	return storage.Fact{Asset: a}
}

func word(i int) string {
	ws := []string{"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel"}
	return ws[hashMod(strconv.Itoa(i), len(ws))]
}

func hashMod(s string, m int) int {
	h := sha256.Sum256([]byte(s))
	return (int(h[0])<<16 + int(h[1])<<8 + int(h[2])) % m
}

// benchBookkeepingID derives the caller-supplied observations.id the same
// way the fixture corpus loader does (fnv1a-64 over a prefix + cursor,
// masked to 63 bits).  Dedup rides on (source_id, source_cursor), never
// on this value; it exists only because observations.id has no default.
func benchBookkeepingID(sourceCursor string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("bench:" + sourceCursor))
	return int64(h.Sum64() & 0x7fff_ffff_ffff_ffff)
}
