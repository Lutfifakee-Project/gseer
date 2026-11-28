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

// import.go — `gseer import` (R58 custom dataset ecosystem): local
// CSV/JSON/JSONL files into the search index with explicit field
// mapping, validation, a dry-run preview, row-numbered error reporting,
// and INCREMENTAL dedup via the standard L1 delivery identity
// (source_id, source_cursor = "row:<n>").  Re-importing the same file
// can never duplicate assets.  Custom data ingests through the SAME
// Fact path as every collector (same validators, same suppression gate,
// same provenance rules) — the core schema and query semantics are not
// touched.  Import never contacts the network.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// importRow is the normalized record one input row maps to.
type importRow struct {
	IP, Domain, Hostname string
	ASN                  int
	ASNOrg, Country      string
	Port                 int
	Protocol             string
	Extra                map[string]any // unmapped columns → evidence evidence.custom
	Line                 int            // 1-based input line/row for error reporting
}

// registerImportCmd attaches `gseer import`.
func registerImportCmd(root *cobra.Command) {
	var (
		fFile        string
		fName        string
		fMap         []string
		fFormat      string
		fDryRun      bool
		fLimit       int
		fAttribution string
		fTemplate    string
	)
	cmd := &cobra.Command{
		Use:   "import --file <path> --name <source-name>",
		Short: "Import a local CSV/JSON/JSONL dataset into the index (validated, deduplicated, incremental)",
		Long: `Import a LOCAL dataset file into the search index (R58).

Formats (auto-detected by extension, --format overrides): .csv, .json
(array of objects), .jsonl/.ndjson (one JSON object per line).

Field mapping (--map target=column, repeatable): every row must resolve to
one asset identity — ip | domain | hostname.  Optional columns: asn,
asn_org, country, port, protocol.  UNMAPPED columns are preserved as
evidence.eustom custom fields — searchable via http.headers-like JSON
paths? No: they are stored under evidence."custom" and visible in
` + "`gseer host --history`" + ` timelines and exports; they do not become
dynamic query fields in this release (documented limitation).

Guarantees:
  - validation: rows that fail are reported with their input line number
    and SKIPPED (import continues; exit code stays 0 unless --strict);
  - deduplication: L1 delivery identity (source, row cursor) — re-running
    the same file inserts NOTHING new;
  - provenance: the rows carry source name + provenance ` + "`custom`" + `;
  - preview: --dry-run shows what WOULD happen without writing;
  - incremental: large files are streamed in batches (--batch).

The import reads ONLY the local file: no network access, no scanning.` + "\n\nExamples:\n" + `
  gseer import --file hosts.csv --name my-assets --dry-run
  gseer import --file hosts.csv --name my-assets --map ip=address --map port=port
  gseer import --file feed.jsonl --name threat-feed --attribution "Internal telemetry"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if fFile == "" || fName == "" {
				printf(out, "E_IMPORT_USAGE: --file and --name are required\nTry: gseer import --file data.csv --name my-dataset --dry-run\n")
				exitWith(ExitInvalidInput)
				return nil
			}
			// R88/R92: import templates — named mapping/format presets so
			// common shapes need no hand-written --map lists.  Explicit
			// --map/--format flags always win over the template defaults.
			if fTemplate != "" {
				tm, tf, tok := importTemplate(fTemplate)
				if !tok {
					printf(out, "E_IMPORT_TEMPLATE: unknown template %q\nSupported: ip-port, domain-list, threat-feed-jsonl\n", fTemplate)
					exitWith(ExitInvalidInput)
					return nil
				}
				if len(fMap) == 0 {
					fMap = tm
				}
				if fFormat == "" {
					fFormat = tf
				}
			}
			if !strings.HasPrefix(fName, "custom-") {
				fName = "custom-" + fName
			}
			ctx := commandContext(cmd)
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			if cfg.Profile != "personal" {
				printf(out, "E_PROFILE_UNSUPPORTED: gseer import runs on the personal (SQLite) store in this release\n")
				exitWith(ExitConfig)
				return nil
			}
			res, oerr := sqlite.Open(cfg.Database.DSN)
			if oerr != nil {
				return oerr
			}
			defer func() { _ = res.DB.Close() }()
			if _, merr := sqlite.Migrate(ctx, res.DB); merr != nil {
				return merr
			}
			st := sqlite.NewStore(res.DB)

			srcID, serr := ensureCustomSource(ctx, res.DB, fName, fAttribution)
			if serr != nil {
				return serr
			}

			rowsCh := make(chan importRow, 256)
			errCh := make(chan importError, 64)
			go func() {
				defer close(rowsCh)
				defer close(errCh)
				streamImportFile(fFile, fFormat, fMap, fLimit, rowsCh, errCh)
			}()

			res2, ierr := ingestImportRows(ctx, out, st, srcID, fName, rowsCh, errCh, fDryRun)
			if ierr != nil {
				return ierr
			}
			printf(out, "import %s: read=%d ingested=%d deduped=%d invalid=%d (source %q, provenance custom)\n",
				filepath.Base(fFile), res2.Read, res2.Ingested, res2.Deduped, res2.Invalid, fName)
			if fDryRun {
				printf(out, "DRY-RUN: nothing was written.\n")
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&fFile, "file", "", "path to the dataset file (required)")
	cmd.Flags().StringVar(&fName, "name", "", "source name (required; prefixed custom-)")
	cmd.Flags().StringSliceVar(&fMap, "map", nil, "field mapping target=column (targets: ip,domain,hostname,asn,asn_org,country,port,protocol)")
	cmd.Flags().StringVar(&fFormat, "format", "", "input format override: csv|json|jsonl")
	cmd.Flags().BoolVar(&fDryRun, "dry-run", false, "validate and preview without writing")
	cmd.Flags().IntVar(&fLimit, "limit", 0, "import at most N rows (0 = all)")
	cmd.Flags().StringVar(&fAttribution, "attribution", "", "attribution/terms note stored with the source")
	cmd.Flags().StringVar(&fTemplate, "template", "", "mapping preset: ip-port (csv) | domain-list (csv) | threat-feed-jsonl (jsonl)")
	root.AddCommand(cmd)
}

// importTemplate returns (mapping, format) for a named template (R88).
func importTemplate(name string) ([]string, string, bool) {
	switch name {
	case "ip-port":
		return []string{"ip=ip", "port=port", "protocol=protocol", "asn_org=org"}, "csv", true
	case "domain-list":
		return []string{"domain=domain"}, "csv", true
	case "threat-feed-jsonl":
		return []string{"ip=ip", "port=port", "protocol=protocol", "asn=asn", "asn_org=org", "country=country"}, "jsonl", true
	}
	return nil, "", false
}

// ensureCustomSource creates (or returns) the data_sources row for a
// custom import source; attribution/terms are recorded on the row.
func ensureCustomSource(ctx context.Context, db *sql.DB, name, attribution string) (int64, error) {
	terms := attribution
	if terms == "" {
		terms = "user-provided local dataset (no upstream source; provenance=custom)"
	}
	var id int64
	err := db.QueryRowContext(ctx, `SELECT id FROM data_sources WHERE name = ?`, name).Scan(&id)
	if err == nil {
		return id, nil
	}
	if err != sql.ErrNoRows {
		return 0, err
	}
	res, err := db.ExecContext(ctx, `INSERT INTO data_sources (name, connector, terms_ref, config, enabled, created_at)
		VALUES (?, 'custom', ?, '{}', 1, ?)`, name, terms, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// importError carries a row-scoped validation/read error.
type importError struct {
	Line int
	Err  error
}

// importResult summarizes one run (R58: honest counts, no silent loss).
type importResult struct {
	Read     int
	Ingested int
	Deduped  int
	Invalid  int
}

// streamImportFile reads the file and pushes normalized rows (with
// line-numbered errors) through the channels; bounded by limit.
func streamImportFile(path, format string, mapping []string, limit int, rows chan<- importRow, errs chan<- importError) {
	m := parseMapping(mapping)
	ext := strings.ToLower(filepath.Ext(path))
	if format == "" {
		switch ext {
		case ".csv":
			format = "csv"
		case ".json":
			format = "json"
		case ".jsonl", ".ndjson":
			format = "jsonl"
		default:
			errs <- importError{Line: 0, Err: fmt.Errorf("unknown input format for %q — pass --format csv|json|jsonl", path)}
			return
		}
	}
	f, err := os.Open(path)
	if err != nil {
		errs <- importError{Line: 0, Err: err}
		return
	}
	defer f.Close()

	send := func(r importRow, line int) bool {
		if limit > 0 && r.Line > limit {
			return false
		}
		rows <- r
		return true
	}

	switch format {
	case "csv":
		cr := csv.NewReader(f)
		cr.FieldsPerRecord = -1
		header, err := cr.Read()
		if err != nil {
			errs <- importError{Line: 0, Err: fmt.Errorf("read csv header: %w", err)}
			return
		}
		idx := resolveCSVColumns(header, m)
		line := 1
		for {
			rec, err := cr.Read()
			if err == io.EOF {
				return
			}
			line++
			if err != nil {
				errs <- importError{Line: line, Err: err}
				continue
			}
			r := rowFromRecord(rec, idx, m, line, header)
			if !send(r, line) {
				return
			}
		}
	case "json":
		var arr []map[string]any
		dec := json.NewDecoder(f)
		if err := dec.Decode(&arr); err != nil {
			errs <- importError{Line: 0, Err: fmt.Errorf("parse json array: %w", err)}
			return
		}
		for i, obj := range arr {
			r := rowFromObject(obj, m, i+1)
			if !send(r, i+1) {
				return
			}
		}
	case "jsonl":
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
		line := 0
		for sc.Scan() {
			line++
			text := sc.Text()
			if strings.TrimSpace(text) == "" {
				continue
			}
			var obj map[string]any
			if err := json.Unmarshal([]byte(text), &obj); err != nil {
				errs <- importError{Line: line, Err: err}
				continue
			}
			r := rowFromObject(obj, m, line)
			if !send(r, line) {
				return
			}
		}
	}
}

// parseMapping turns "ip=address,port=portno" pairs into a map.
func parseMapping(mapping []string) map[string]string {
	m := map[string]string{}
	for _, kv := range mapping {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			m[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return m
}

// resolveCSVColumns picks column indexes for mapped targets; unmapped
// targets default to same-named columns when present.
func resolveCSVColumns(header []string, m map[string]string) map[string]int {
	idx := map[string]int{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		for _, hi := range h {
			_ = hi
		}
		if _, ok := idx[h]; !ok {
			idx[h] = i
		}
	}
	resolved := map[string]int{}
	for target, col := range m {
		if i, ok := idx[strings.ToLower(col)]; ok {
			resolved[target] = i
		}
	}
	for _, target := range []string{"ip", "domain", "hostname", "asn", "asn_org", "country", "port", "protocol"} {
		if _, ok := resolved[target]; !ok {
			if i, ok := idx[target]; ok {
				resolved[target] = i
			}
		}
	}
	return resolved
}

// rowFromRecord normalizes one CSV row.
func rowFromRecord(rec []string, idx map[string]int, m map[string]string, line int, header []string) importRow {
	get := func(target string) string {
		if i, ok := idx[target]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}
	r := importRow{Line: line,
		IP: get("ip"), Domain: get("domain"), Hostname: get("hostname"),
		ASNOrg: get("asn_org"), Country: get("country"), Protocol: get("protocol"),
	}
	if v := get("asn"); v != "" {
		r.ASN, _ = strconv.Atoi(v)
	}
	if v := get("port"); v != "" {
		r.Port, _ = strconv.Atoi(v)
	}
	r.Extra = map[string]any{}
	used := map[int]bool{}
	for _, i := range idx {
		used[i] = true
	}
	for i, h := range header {
		if used[i] || i >= len(rec) || strings.TrimSpace(rec[i]) == "" {
			continue
		}
		r.Extra[h] = rec[i]
	}
	return r
}

// rowFromObject normalizes one JSON object row (mapping keys, defaults
// to same-named keys).
func rowFromObject(obj map[string]any, m map[string]string, line int) importRow {
	get := func(target string) string {
		key := target
		if c, ok := m[target]; ok {
			key = c
		}
		if v, ok := obj[key]; ok {
			switch t := v.(type) {
			case string:
				return strings.TrimSpace(t)
			case float64:
				return strconv.FormatInt(int64(t), 10)
			}
		}
		return ""
	}
	r := importRow{Line: line,
		IP: get("ip"), Domain: get("domain"), Hostname: get("hostname"),
		ASNOrg: get("asn_org"), Country: get("country"), Protocol: get("protocol"),
	}
	if v := get("asn"); v != "" {
		r.ASN, _ = strconv.Atoi(v)
	}
	if v := get("port"); v != "" {
		r.Port, _ = strconv.Atoi(v)
	}
	r.Extra = map[string]any{}
	mapped := map[string]bool{}
	for _, c := range m {
		mapped[c] = true
	}
	for k, v := range obj {
		if mapped[k] || v == nil {
			continue
		}
		r.Extra[k] = v
	}
	return r
}

// validateImportRow enforces the identity contract: exactly one asset
// identity per row, port in range.  It ALSO normalizes a mis-mapped ip
// column: a non-IP value containing a dot is a hostname (R58
// normalization) — the ip field moves to Hostname instead of failing the
// whole batch.
func validateImportRow(r importRow) error {
	if r.IP != "" {
		if _, err := netip.ParseAddr(r.IP); err != nil {
			if strings.Contains(r.IP, ".") {
				// hostname placed in the ip column — normalize.
				r.Hostname = r.IP
				r.IP = ""
			} else {
				return fmt.Errorf("ip %q is not a valid IP address", r.IP)
			}
		}
	}
	idCount := 0
	for _, v := range []string{r.IP, r.Domain, r.Hostname} {
		if v != "" {
			idCount++
		}
	}
	if idCount == 0 {
		return fmt.Errorf("no asset identity (need one of ip/domain/hostname)")
	}
	if r.Port != 0 && (r.Port < 1 || r.Port > 65535) {
		return fmt.Errorf("port %d outside 1..65535", r.Port)
	}
	return nil
}

// ingestImportRows consumes the streamed rows and ingests valid ones via
// the standard Fact path (same suppression gate + validators).
func ingestImportRows(ctx context.Context, out io.Writer, st *sqlite.Store, srcID int64, sourceName string, rows <-chan importRow, errs <-chan importError, dryRun bool) (importResult, error) {
	var res importResult
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	batch := make([]storage.Fact, 0, 500)
	var invalids []string

	flush := func() error {
		if dryRun || len(batch) == 0 {
			batch = batch[:0]
			return nil
		}
		stats, err := st.IngestFacts(ctx, batch)
		if err != nil {
			return fmt.Errorf("ingest batch: %w", err)
		}
		res.Ingested += stats.AssetsInserted + stats.AssetsUpdated
		res.Deduped += stats.ObservationsDeduped
		batch = batch[:0]
		return nil
	}

	done := false
	for !done {
		select {
		case r, ok := <-rows:
			if !ok {
				done = true
				break
			}
			res.Read++
			if verr := validateImportRow(r); verr != nil {
				res.Invalid++
				if len(invalids) < 10 {
					invalids = append(invalids, fmt.Sprintf("line %d: %v", r.Line, verr))
				}
				continue
			}
			f := buildImportFact(srcID, sourceName, r, base)
			batch = append(batch, f)
			if len(batch) >= 500 {
				if err := flush(); err != nil {
					return res, err
				}
			}
		case ie, ok := <-errs:
			if !ok {
				// drain remaining rows until rows closes
				for r := range rows {
					res.Read++
					if verr := validateImportRow(r); verr != nil {
						res.Invalid++
						if len(invalids) < 10 {
							invalids = append(invalids, fmt.Sprintf("line %d: %v", r.Line, verr))
						}
					} else {
						batch = append(batch, buildImportFact(srcID, sourceName, r, base))
						if len(batch) >= 500 {
							if err := flush(); err != nil {
								return res, err
							}
						}
					}
				}
				done = true
				break
			}
			res.Invalid++
			if ie.Line == 0 {
				return res, fmt.Errorf("E_IMPORT_INPUT: %w", ie.Err)
			}
			if len(invalids) < 10 {
				invalids = append(invalids, fmt.Sprintf("line %d: %v", ie.Line, ie.Err))
			}
		}
	}
	if err := flush(); err != nil {
		return res, err
	}
	if len(invalids) > 0 {
		printf(out, "%d invalid row(s), first %d:\n", res.Invalid, len(invalids))
		for _, s := range invalids {
			printf(out, "  - %s\n", s)
		}
	}
	return res, nil
}

// buildImportFact maps a normalized row to the storage Fact (provenance
// custom, cursor row:<line> for L1 incremental dedup).
func buildImportFact(srcID int64, sourceName string, r importRow, base time.Time) storage.Fact {
	kind := storage.AssetKindIP
	value := r.IP
	var typed *string
	switch {
	case r.IP != "":
		if _, err := netip.ParseAddr(r.IP); err != nil && strings.Contains(r.IP, ".") {
			// Same normalization as validateImportRow (R58).
			r.Hostname = r.IP
			r.IP = ""
		}
	}
	switch {
	case r.IP != "":
		kind, value, typed = storage.AssetKindIP, r.IP, &r.IP
	case r.Domain != "":
		kind, value, typed = storage.AssetKindDomain, r.Domain, &r.Domain
	default:
		kind, value, typed = storage.AssetKindHostname, r.Hostname, &r.Hostname
	}
	a := storage.Asset{
		Kind: kind, Value: value, Sources: []string{sourceName},
		ASNOrg:     r.ASNOrg,
		GeoCountry: r.Country,
		ASN:        r.ASN,
		FirstSeen:  base,
		LastSeen:   base,
	}
	switch kind {
	case storage.AssetKindIP:
		a.IP = typed
	case storage.AssetKindDomain:
		a.Domain = typed
	default:
		a.Hostname = typed
	}
	f := storage.Fact{Asset: a}
	if r.Port != 0 {
		f.Service = &storage.Service{
			Port: r.Port, Transport: "tcp",
			Protocol:  firstNonEmpty(r.Protocol, "tcp"),
			FirstSeen: base, LastSeen: base,
		}
	}
	// Payload hash over the row identity — the L2 fact identity that
	// makes re-imports of unchanged rows dedup silently.
	hash := sha256.Sum256([]byte(fmt.Sprintf("%s|%d|%d|%s|%s",
		value, r.Port, r.ASN, r.ASNOrg, r.Country)))
	f.Observation = storage.Observation{
		SourceID:     srcID,
		SourceCursor: fmt.Sprintf("row:%d", r.Line),
		ObservedAt:   base,
		Provenance:   "custom",
		PayloadHash:  hex.EncodeToString(hash[:]),
		Evidence:     map[string]any{"custom": r.Extra},
	}
	// Caller-supplied bookkeeping id (same derivation contract as the
	// other writers).
	f.Observation.ID = importBookkeepingID(f.Observation.SourceCursor)
	return f
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// importBookkeepingID mirrors the fixture/bench derivation (fnv1a-64
// masked to 63 bits) — dedup rides on (source_id, source_cursor).
func importBookkeepingID(cursor string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("import:" + cursor))
	return int64(h.Sum64() & 0x7fff_ffff_ffff_ffff)
}
