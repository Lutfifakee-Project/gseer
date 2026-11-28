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

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
	"github.com/Lutfifakee-Project/gseer/internal/search"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// search.go — `gseer search <query>` (SPEC-03 §2/§3), the M10/M11
// implementation.  The CLI is a thin renderer over the SAME
// SearchService the REST API and dashboard use: GQL semantics,
// pagination, and freshness notices are identical on every surface.
//
// Search never triggers scanning (ADR-0010): the command reads the
// configured index (self-hosted: the local search_index view; client:
// the configured endpoint's REST API) and performs no network egress
// of its own beyond the client-profile call to the user's own endpoint.

// registerSearchCmd attaches the `gseer search <query>` command.
func registerSearchCmd(root *cobra.Command) {
	var (
		fLimit     int
		fCursor    string
		fSort      string
		fMode      string
		fFormat    string
		fFacets    bool
		fFacetDims []string
		fMaxValues int
		fExplain   bool
		fValidate  bool
		fTimeout   time.Duration
		fFields    []string
		fCollapse  bool
		fPreset    string
	)
	// searchFlagsReset mirrors collectRunReset/redriveReset/sourceAddReset:
	// cobra flag values persist across Execute() calls on the shared
	// RootCmd, so a test that sets --facet (StringSlice) leaks the value
	// into later tests that invoke `search` without --facet.  The seam is
	// a no-op in production (the singleton command keeps its parsed flags
	// for one process lifetime); tests reset between invocations.
	searchFlagsReset = func() {
		fLimit = 0
		fCursor = ""
		fSort = ""
		fMode = ""
		fFormat = ""
		fFacets = false
		fFacetDims = nil
		fMaxValues = 0
		fExplain = false
		fValidate = false
		fTimeout = 0
		fFields = nil
		fCollapse = false
		fPreset = ""
	}
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search the configured index with GQL",
		Long: `Search the configured index with GQL.

GQL is the GSEER Query Language.  Examples:
  gseer search 'port=443'
  gseer search 'title="phpMyAdmin"'
  gseer search 'server="nginx" && port=443'
  gseer search 'ip IN_CIDR "203.0.113.0/24"'

The query is validated first; errors point at the exact position with a
concrete Try: hint.  Searches run against the configured index only —
search never triggers scanning (no network egress by any search path).

Field registry (canonical names + aliases; operators per field):
  ip                    ==, !=, IN, IN_CIDR
  asset_value           ==, !=, IN, CONTAINS
  asset_kind            ==, !=, IN
  domain, hostname      ==, !=, IN, CONTAINS, IN_DOMAIN
  asn                   ==, !=, IN, <, <=, >, >=
  asn_org, geo_city     ==, !=, IN, CONTAINS
  country, region       ==, !=, IN            (geo_country / geo_region)
  port                  ==, !=, IN, <, <=, >, >=
  transport, protocol   ==, !=, IN
  name, product, version, server                   ==, !=, IN, CONTAINS
  status                ==, !=, IN, <, <=, >, >=   (http.status)
  title                 ==, !=, IN, CONTAINS       (http.title)
  tls_version           ==, !=, IN
  cert_subject_cn, cert_issuer_cn                  ==, !=, IN, CONTAINS
  cert_expiry, first_seen, last_seen               ==, !=, IN, <, <=, >, >=
  tech, fingerprint     CONTAINS              (technologies)
  sources               CONTAINS
  stale                 ==, !=   ("true"/"false")
  coverage              ==, !=, IN, CONTAINS   (the P4 coverage class,
                        strongest evidence wins: discovered |
                        dns-resolved | routing-confirmed |
                        tls-observed | http-observed |
                        service-observed)
  evidence              CONTAINS               (provenance families:
                        ct | dns | bgp | asn | http | tls)
  last_observed, observed_after, observed_before   ==, !=, <, <=, >, >=

R37 fields: prefix (==, !=, IN, *=, CONTAINS — the asset's latest
                        IP-to-ASN / BGP attribution prefix, e.g.
                        prefix=="2001:1201::/32"),
  banner               *=, ==, !=, CONTAINS    (service banner evidence),
  tls.cert_issuer_org  ==, !=, *=, CONTAINS    (issuing organization),
  http.headers         CONTAINS, ==            (the whole captured
                        headers JSON, e.g. http.headers CONTAINS
                        "cloudflare"),
  http.header.<name>   ==, !=, *=, CONTAINS    (ONE captured header by
                        lowercase name: http.header.x-powered-by ==
                        "Next.js"; filter-only — project the whole
                        http.headers column instead).

Quantifiers: ANY(host){ ... } — the host matches when ANY of its
services satisfies the body.  ALL is planned for a later version.

Quoting: strings are double-quoted; bare numbers are integers (typing
is strict — port==443, not port=="443").

Output modes (R46):
  --format table|json|csv|ndjson   (alias of --output/-o; csv = RFC 4180
                                   with a header, ndjson = one JSON row
                                   object per line for pipes)
  --fields ip,port,domain,hostname project those columns (text/csv)
  --quiet                          rows only: no notice, no summary, no
                                   paging hint (stable for pipelines)
Errors in json/csv/ndjson modes go to STDERR as one JSON object; stdout
stays clean for jq/awk/redirects.  Exit codes (SPEC-03 §9): 0 ok,
2 invalid query/usage, 4 config, 5 database unavailable, 10 internal.

Examples (FOFA/Shodan-style, real fields):
  gseer search 'ip == "1.0.0.0"'
  gseer search 'prefix == "2001:1201::/32" OR asn == 28498'
  gseer search 'banner *= "*OpenSSH*" AND port < 1024'
  gseer search 'http.title CONTAINS "Example" && http.header.server == "cloudflare"'
  gseer search 'coverage == "routing-confirmed" && is_ipv6 == true' --sort last_seen:desc
  gseer search 'tls.cert_issuer_org CONTAINS "SSL Corporation"' --facets`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSearch(cmd, args, searchFlags{
				Limit: fLimit, Cursor: fCursor, Sort: fSort, Mode: fMode,
				Format: fFormat,
				Facets: fFacets, FacetDims: fFacetDims, MaxValues: fMaxValues,
				Explain: fExplain, Validate: fValidate, Timeout: fTimeout,
				Fields: fFields, Collapse: fCollapse, Preset: fPreset,
			})
		},
	}
	cmd.Flags().IntVar(&fLimit, "limit", 0, "maximum results (0 = server default 100, hard cap 1000)")
	cmd.Flags().StringVar(&fCursor, "cursor", "", "pagination cursor from a prior result")
	cmd.Flags().StringVar(&fSort, "sort", "", `sort fields, e.g. "last_seen:desc", "last_observed:desc" or "coverage:desc" (evidence-strength; default: last_seen:desc)`)
	cmd.Flags().StringVar(&fMode, "mode", "", "search mode: service (default, one row per service) | asset (one row per asset)")
	// R46: --format is the search-local alias of the global --output/-o
	// (the documented user workflow writes `gseer search '...' --format json`).
	cmd.Flags().StringVar(&fFormat, "format", "", "output format: table|json|csv|ndjson (alias of --output/-o)")
	cmd.Flags().StringVar(&fPreset, "preset", "", "run a saved preset (gseer preset add NAME 'GQL'); explicit flags override the preset's sort/mode")
	cmd.Flags().BoolVar(&fFacets, "facets", false, "also compute facet aggregates (port, protocol, technology, service, country, source, freshness) over the same filtered rows")
	cmd.Flags().StringSliceVar(&fFacetDims, "facet", nil, "restrict facets to these dimensions (comma-separated)")
	cmd.Flags().IntVar(&fMaxValues, "max-values", 0, "facet values per dimension (default 10, hard cap 50)")
	cmd.Flags().BoolVar(&fExplain, "explain", false, "print the compiled query plan (AST → branch → SQL) and exit")
	cmd.Flags().BoolVar(&fValidate, "validate", false, "validate the query and exit (no execution)")
	cmd.Flags().DurationVar(&fTimeout, "timeout", 0, "per-query time budget (default 5s, hard cap 30s)")
	cmd.Flags().StringSliceVar(&fFields, "fields", nil, "projection fields (default: all search_index columns)")
	// --collapse is reserved: registered, help-marked "planned", invocation
	// exits 64 per SPEC-03 §3 (design at v0.1.0, D-13).
	cmd.Flags().BoolVar(&fCollapse, "collapse", false, "PLANNED (D-13); invocation exits 64")
	_ = cmd.Flags().MarkHidden("collapse")

	root.AddCommand(cmd)
}

// searchFlags carries the parsed search command flags into runSearch so
// the function does not read them from the shared cobra command (which
// would re-introduce the cross-test leak the seam exists to prevent).
type searchFlags struct {
	Limit     int
	Cursor    string
	Sort      string
	Mode      string
	Format    string
	Facets    bool
	FacetDims []string
	MaxValues int
	Explain   bool
	Validate  bool
	Timeout   time.Duration
	Fields    []string
	Collapse  bool
	Preset    string
}

// searchFlagsReset is the test seam that clears the sticky search flag
// values (cobra flags persist on the shared RootCmd between Execute
// calls).  It is a no-op in production; tests call it between
// invocations that set --facet/--facets/--max-values/--collapse so a
// later `search` in the same test binary does not inherit them.
var searchFlagsReset = func() {}

func runSearch(cmd *cobra.Command, args []string, sf searchFlags) error {
	out := cmd.OutOrStdout()
	gql := ""
	if len(args) > 0 {
		gql = args[0]
	}
	// R60: --preset loads a saved query (gql + default sort/mode) from the
	// personal index.  Explicit flags win over the preset's defaults;
	// explicit overrides of the preset's GQL are not supported (one query
	// at a time — pass a bare GQL instead).
	if sf.Preset != "" {
		gqlSaved, sortSaved, modeSaved, perr := loadSearchPreset(cmd, sf.Preset)
		if perr != nil {
			printf(out, "E_PRESET_NOT_FOUND: %s\nTry: gseer preset list\n", perr.Error())
			exitWith(ExitInvalidInput)
			return nil
		}
		if gql == "" {
			gql = gqlSaved
		}
		if sf.Sort == "" {
			sf.Sort = sortSaved
		}
		if sf.Mode == "" {
			sf.Mode = modeSaved
		}
	}
	if gql == "" {
		printf(out, "E_QUERY_USAGE: a GQL expression or --preset NAME is required\nTry: gseer search 'port == 443'  or  gseer search --preset my-query\n")
		exitWith(ExitInvalidInput)
		return nil
	}

	// R46: --format (search-local) overrides the global --output/-o when
	// set.  Unknown formats are a usage error, not a silent table
	// fallback — never advertise what is not implemented.
	if sf.Format != "" {
		switch sf.Format {
		case "table", "json", "csv", "ndjson":
			flags.output = sf.Format
		default:
			printf(out, "E_QUERY_FORMAT: unknown --format %q\nWhy: search supports table|json|csv|ndjson (yaml is not implemented for search)\nTry: gseer search %q --format json\n", sf.Format, gql)
			exitWith(ExitInvalidInput)
		}
	}

	if sf.Collapse {
		printf(out, "gseer search --collapse is PLANNED (D-13); invocation exits 64 per SPEC-03 §3.\n")
		exitWith(ExitUsagePlanned)
	}
	fFacets := sf.Facets
	if len(sf.FacetDims) > 0 {
		fFacets = true
	}

	q := search.Query{
		GQL:       gql,
		Mode:      sf.Mode,
		Sort:      sf.Sort,
		Limit:     sf.Limit,
		Timeout:   sf.Timeout,
		Cursor:    sf.Cursor,
		Fields:    sf.Fields,
		WithStats: true,
	}

	// --validate / --explain: compile only, no database contact and no
	// configuration required (a fresh install can validate a query
	// before anything is initialized).
	if sf.Validate || sf.Explain {
		svc := search.New(nil)
		plan, err := svc.Plan(q)
		if err != nil {
			printf(out, "%s\n", err.Error())
			exitWith(ExitInvalidInput)
		}
		if sf.Validate && !sf.Explain {
			printf(out, "valid GQL ✓  (mode=%s, branch=%s)\n", plan.Mode, plan.Branch)
			return nil
		}
		printf(out, "%s\n", plan.Explain())
		return nil
	}

	cfg, cerr := engineConfigOrInit(cmd)
	if cerr != nil {
		printf(out, "%s\nTry: gseer setup --help\n", cerr.Error())
		exitWith(ExitConfig)
	}

	switch cfg.Profile {
	case config.ProfilePersonal:
		return runPersonalSearch(out, cfg, q, facetsRequest{Enabled: fFacets, Dims: sf.FacetDims, MaxValues: sf.MaxValues})
	default:
		return localSearch(out, cfg, q, facetsRequest{Enabled: fFacets, Dims: sf.FacetDims, MaxValues: sf.MaxValues})
	}
}

// facetsRequest carries the CLI facet flags into the search paths.
type facetsRequest struct {
	Enabled   bool
	Dims      []string
	MaxValues int
}

// ---------------------------------------------------------------------------
// Self-hosted: query the local index directly through the SearchService
// ---------------------------------------------------------------------------

func localSearch(out io.Writer, cfg *config.Config, q search.Query, fr facetsRequest) error {
	// Give the overall context generous headroom beyond the query's own
	// statement timeout (connect + stats round-trips).
	budget := 45 * time.Second
	if q.Timeout > 0 {
		budget = q.Timeout + 30*time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	// Runtime data plane: prefer the least-privilege gseer_app
	// credential; the fallback to the operator credential is explicit
	// (runtimeCommandDSN), never silent.
	pool, err := pgxpool.New(ctx, runtimeCommandDSN(out, cfg))
	if err != nil {
		printf(out, "E_DB_UNAVAILABLE: cannot open the database pool\nWhy: %v\nTry: check database.dsn in the config — gseer doctor\n", err)
		exitWith(ExitUnavailable)
	}
	defer pool.Close()

	svc := search.New(pool)
	res, err := svc.Search(ctx, q)
	if err != nil {
		renderSearchError(out, err)
		exitWith(searchExitCode(err))
	}

	// Facets (v0.1.0): the SAME GQL filter runs through the SAME
	// SearchService; the aggregates narrow exactly the rows the search
	// returned.
	var fres *search.FacetsResult
	if fr.Enabled {
		fres, err = svc.Facets(ctx, search.FacetsQuery{
			GQL: q.GQL, Mode: q.Mode, Timeout: q.Timeout,
			MaxValues: fr.MaxValues, Facets: fr.Dims,
		})
		if err != nil {
			renderSearchError(out, err)
			exitWith(searchExitCode(err))
		}
	}
	renderSearchWithFacets(out, res, fres, jsonOutput(), q.Fields)
	return nil
}

// renderSearchWithFacets renders the result and, when present, the
// facet aggregates (JSON: a facets key; table: a compact section).
func renderSearchWithFacets(out io.Writer, res *search.Result, fres *search.FacetsResult, asJSON bool, fields []string) {
	if fres == nil {
		renderResult(out, res, asJSON, fields)
		return
	}
	switch {
	case asJSON:
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{
			"rows":        res.Rows,
			"count":       res.Query.RowCount,
			"has_more":    res.HasMore,
			"next_cursor": res.NextCursor,
			"notice":      res.Notice,
			"query":       res.Query,
			"facets":      fres.Facets,
		})
	case outputMode() == "csv":
		renderRowsCSV(out, res, fields)
		printf(out, "\n")
		renderFacetsTable(out, fres)
	case outputMode() == "ndjson":
		renderRowsNDJSON(out, res)
		renderFacetsNDJSON(out, fres)
	default:
		renderResult(out, res, asJSON, fields)
		renderFacetsTable(out, fres)
	}
}

// renderFacetsTable prints the facet aggregates in the compact text form.
func renderFacetsTable(out io.Writer, fres *search.FacetsResult) {
	printf(out, "\nFacets (same filter, same SearchService):\n")
	for _, f := range fres.Facets {
		if len(f.Values) == 0 {
			printf(out, "  %-11s (no values)\n", f.Name)
			continue
		}
		parts := make([]string, 0, len(f.Values))
		for _, v := range f.Values {
			parts = append(parts, fmt.Sprintf("%s (%d)", v.Value, v.Count))
		}
		line := strings.Join(parts, ", ")
		if f.Truncated {
			line += ", …"
		}
		printf(out, "  %-11s %s\n", f.Name, line)
	}
}

// renderFacetsNDJSON emits one compact JSON object per facet after the
// row objects (same stream, machine-readable).
func renderFacetsNDJSON(out io.Writer, fres *search.FacetsResult) {
	for _, f := range fres.Facets {
		enc := json.NewEncoder(out)
		_ = enc.Encode(map[string]any{"facet": f.Name, "values": f.Values, "truncated": f.Truncated})
	}
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

func jsonOutput() bool {
	return flags.output == "json"
}

// outputMode reports the normalized search output format.  Anything the
// search renderer does not implement falls back to the human table
// (unknown formats are rejected earlier in runSearch).
func outputMode() string {
	switch flags.output {
	case "json", "csv", "ndjson":
		return flags.output
	default:
		return "table"
	}
}

// renderResult renders the search result in the requested output mode.
// table (default): human lines + summary + next-page hint; json: the
// full envelope; csv: RFC 4180 rows with a header (--fields honored);
// ndjson: one compact JSON object per row, machines first.
func renderResult(out io.Writer, res *search.Result, asJSON bool, fields []string) {
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		payload := map[string]any{
			"rows":        res.Rows,
			"count":       res.Query.RowCount,
			"has_more":    res.HasMore,
			"next_cursor": res.NextCursor,
			"query":       res.Query,
			"notice":      res.Notice,
		}
		if res.Index != nil {
			payload["index"] = res.Index
		}
		_ = enc.Encode(payload)
		return
	}
	switch outputMode() {
	case "csv":
		renderRowsCSV(out, res, fields)
		return
	case "ndjson":
		renderRowsNDJSON(out, res)
		return
	}

	quiet := flags.quiet
	if !quiet && res.Notice != "" {
		printf(out, "--- %s\n\n", res.Notice)
	}
	if !quiet {
		printf(out, "%d result(s) in %d ms  (mode=%s)\n", res.Query.RowCount, res.Query.TookMs, res.Query.Mode)
	}
	// R37: the --fields projection renders in TEXT mode too — the
	// search-engine UX prints the columns the operator asked for (with
	// a header row) instead of the fixed default line.  JSON output
	// already honored --fields.  The flag value lives on the command
	// (the command-builder closure owns the variable).
	if len(fields) > 0 && len(res.Rows) > 0 {
		known := make([]string, 0, len(fields))
		for _, f := range fields {
			if _, ok := rowFieldText(nil, f); ok {
				known = append(known, f)
			}
		}
		if len(known) > 0 {
			fields = known
		}
		if !quiet {
			printf(out, "  %s\n", strings.Join(fields, "  "))
		}
		for _, r := range res.Rows {
			cells := make([]string, 0, len(fields))
			for _, f := range fields {
				v, _ := rowFieldText(&r, f)
				cells = append(cells, v)
			}
			printf(out, "  %s\n", strings.Join(cells, "  "))
		}
	} else {
		for _, r := range res.Rows {
			printf(out, "  %s\n", rowLine(r))
		}
	}
	// Small result sets get the full-detail hint; wide tables stay one line.
	if !quiet && res.HasMore && res.NextCursor != "" {
		printf(out, "\nNext page: append --cursor %s\n", res.NextCursor)
	}
}

// csvSearchFields is the default CSV projection when --fields is not
// given (a fixed, documented column set — stable for pipelines).
var csvSearchFields = []string{
	"asset_value", "asset_kind", "port", "transport", "protocol",
	"asn", "asn_org", "country", "coverage", "last_seen",
}

// renderRowsCSV writes the result rows as RFC 4180 CSV with a header
// row.  --fields selects the columns (the same names the text table
// accepts); the default is csvSearchFields.
func renderRowsCSV(out io.Writer, res *search.Result, fields []string) {
	if len(fields) == 0 {
		fields = csvSearchFields
	}
	known := make([]string, 0, len(fields))
	for _, f := range fields {
		if _, ok := rowFieldText(nil, f); ok {
			known = append(known, f)
		}
	}
	if len(known) == 0 {
		known = csvSearchFields
	}
	w := csv.NewWriter(out)
	_ = w.Write(known)
	for _, r := range res.Rows {
		rec := make([]string, 0, len(known))
		for _, f := range known {
			v, _ := rowFieldText(&r, f)
			rec = append(rec, v)
		}
		_ = w.Write(rec)
	}
	w.Flush()
}

// renderRowsNDJSON writes one compact JSON object per row — the
// machine-first pipe format (row objects only; use --format json for
// the full envelope with cursor/notice).
func renderRowsNDJSON(out io.Writer, res *search.Result) {
	enc := json.NewEncoder(out)
	for _, r := range res.Rows {
		_ = enc.Encode(r)
	}
}

// rowLine renders one result row in the compact single-line table form.
func rowLine(r search.Row) string {
	line := fmt.Sprintf("%-30s %-9s %-11s %-9s",
		r.AssetValue, r.AssetKind,
		":"+itoa2(r.Port)+"/"+deref(r.Transport),
		deref(r.Protocol))
	if r.Product != nil {
		p := *r.Product
		if len(p) > 20 {
			p = p[:17] + "..."
		}
		line += " " + p
	}
	if r.HTTPStatus != nil {
		line += fmt.Sprintf(" [%d]", *r.HTTPStatus)
	}
	if r.HTTPTitle != nil {
		t := *r.HTTPTitle
		if len(t) > 24 {
			t = t[:21] + "..."
		}
		line += " " + t
	}
	return strings.TrimRight(line, " ")
}

// rowFieldText renders one canonical search field for the TEXT --fields
// table (R37): the value or "-".  ok reports whether the field is one of
// the known text-renderable fields.
func rowFieldText(r *search.Row, field string) (string, bool) {
	if r == nil {
		return "", true
	}
	d := func(s *string) string {
		if s == nil {
			return "-"
		}
		return *s
	}
	switch field {
	case "ip":
		// R46: when --fields projects the typed ip column, the value lives
		// in r.IP (the projection excludes asset_value); fall back to the
		// row's primary value for rows scanned without the ip column.
		if r.IP != nil {
			return *r.IP, true
		}
		return r.AssetValue, true
	case "domain":
		if r.Domain != nil {
			return *r.Domain, true
		}
		return r.AssetValue, true
	case "hostname":
		if r.Hostname != nil {
			return *r.Hostname, true
		}
		return r.AssetValue, true
	case "asset_value":
		return r.AssetValue, true
	case "asset_kind":
		return r.AssetKind, true
	case "country", "geo_country":
		// R46: the CSV/--fields table accepts the canonical alias the
		// query language uses (country) as well as the column name.
		return d(r.GeoCountry), true
	case "asn":
		if r.ASN == nil {
			return "-", true
		}
		return strconv.Itoa(*r.ASN), true
	case "asn_org":
		return d(r.ASNOrg), true
	case "port":
		if r.Port == nil {
			return "-", true
		}
		return strconv.Itoa(*r.Port), true
	case "protocol":
		return d(r.Protocol), true
	case "transport":
		return d(r.Transport), true
	case "http.status":
		if r.HTTPStatus == nil {
			return "-", true
		}
		return strconv.Itoa(*r.HTTPStatus), true
	case "http.title":
		return d(r.HTTPTitle), true
	case "http.server":
		return d(r.HTTPServer), true
	case "tls.version":
		return d(r.TLSVersion), true
	case "tls.cert_subject_cn":
		return d(r.TLSCertSubjectCN), true
	case "tls.cert_issuer_cn":
		return d(r.TLSCertIssuerCN), true
	case "tls.cert_issuer_org":
		return d(r.CertIssuerOrg), true
	case "prefix", "ip_prefix":
		return d(r.IPPrefix), true
	case "banner":
		return d(r.Banner), true
	case "coverage":
		return d(r.CoverageClass), true
	case "ct.log", "ct_log":
		return d(r.CTLog), true
	case "ct.entry_type", "ct_type":
		return d(r.CTEntryType), true
	case "ct.subject", "ct.subject_cn", "ct_subject_cn":
		return d(r.CTSubjectCN), true
	case "ct.issuer":
		return d(r.CTIssuer), true
	case "ct.leaf_sha256":
		return d(r.CTLeafSHA256), true
	case "ct.not_before":
		return d(r.CTNotBefore), true
	case "ct.not_after":
		return d(r.CTNotAfter), true
	case "ct.cert_timestamp":
		return d(r.CTCertTimestamp), true
	case "last_observed":
		if r.LastObserved.IsZero() {
			return "-", true
		}
		return r.LastObserved.Format(time.RFC3339), true
	case "last_seen":
		if r.LastSeen.IsZero() {
			return "-", true
		}
		return r.LastSeen.Format(time.RFC3339), true
	}
	return "-", false
}

func deref(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

func itoa2(n *int) string {
	if n == nil {
		return "-"
	}
	return fmt.Sprintf("%d", *n)
}

// renderSearchError prints the error in the SPEC-03 §7 shape and maps
// PG-level surprises (unmigrated index) to actionable pointers.  In a
// machine output mode (json/csv/ndjson) the error goes to STDERR as one
// compact JSON object so stdout stays a clean pipe surface.
func renderSearchError(out io.Writer, err error) {
	if mode := outputMode(); mode != "table" {
		enc := json.NewEncoder(os.Stderr)
		_ = enc.Encode(map[string]string{"error": err.Error(), "format": mode})
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
		printf(out, "E_DB_NOT_MIGRATED: the search index does not exist yet\n"+
			"Why: the database schema has not been provisioned (%s)\n"+
			"Try: gseer setup --self-hosted   (provisions the schema; add --load-fixtures for evaluation data)\n", pgErr.Message)
		return
	}
	printf(out, "%s\n", err.Error())
}

func searchExitCode(err error) int {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
		return ExitUnavailable // index not provisioned — a service state
	}
	switch {
	case search.AsUnavailable(err):
		return ExitUnavailable
	case search.AsTimeout(err):
		return ExitUnavailable
	default:
		if _, ok := search.AsQuery(err); ok {
			return ExitInvalidInput
		}
		return ExitInternal
	}
}

// exitWith terminates with the SPEC-03 §9 exit code (os.Exit from a
// helper keeps the RunE call sites readable).
func exitWith(code int) {
	exitFunc(code)
}

// exitFunc is the process-exit seam (tests substitute it).
var exitFunc = exitOS

func exitOS(code int) { os.Exit(code) }

// planner import guard: keep the hard cap constant referenced for help
// text parity.
var _ = planner.MaxLimit

// loadSearchPreset reads one saved preset (R60) from the personal index.
func loadSearchPreset(cmd *cobra.Command, name string) (gql, sort, mode string, err error) {
	cfg, cerr := engineConfigOrInit(cmd)
	if cerr != nil {
		return "", "", "", cerr
	}
	if cfg.Profile != "personal" {
		return "", "", "", fmt.Errorf("presets run on the personal (SQLite) store in this release")
	}
	res, oerr := openPersonal(cfg)
	if oerr != nil {
		return "", "", "", oerr
	}
	defer func() { _ = res.DB.Close() }()
	ctx := commandContext(cmd)
	if _, merr := sqlite.Migrate(ctx, res.DB); merr != nil {
		return "", "", "", merr
	}
	row := res.DB.QueryRowContext(ctx, `SELECT gql, COALESCE(sort,''), COALESCE(mode,'') FROM search_presets WHERE name = ?`, name)
	if err := row.Scan(&gql, &sort, &mode); err != nil {
		return "", "", "", fmt.Errorf("no preset named %q", name)
	}
	return gql, sort, mode, nil
}
