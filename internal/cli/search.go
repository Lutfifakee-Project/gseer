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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
	"github.com/Lutfifakee-Project/gseer/internal/search"
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
		fFacets    bool
		fFacetDims []string
		fMaxValues int
		fExplain   bool
		fValidate  bool
		fTimeout   time.Duration
		fFields    []string
		fCollapse  bool
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
		fFacets = false
		fFacetDims = nil
		fMaxValues = 0
		fExplain = false
		fValidate = false
		fTimeout = 0
		fFields = nil
		fCollapse = false
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

Quantifiers: ANY(host){ ... } — the host matches when ANY of its
services satisfies the body.  ALL is planned for a later version.

Quoting: strings are double-quoted; bare numbers are integers (typing
is strict — port==443, not port=="443").`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSearch(cmd, args, searchFlags{
				Limit: fLimit, Cursor: fCursor, Sort: fSort, Mode: fMode,
				Facets: fFacets, FacetDims: fFacetDims, MaxValues: fMaxValues,
				Explain: fExplain, Validate: fValidate, Timeout: fTimeout,
				Fields: fFields, Collapse: fCollapse,
			})
		},
	}
	cmd.Flags().IntVar(&fLimit, "limit", 0, "maximum results (0 = server default 100, hard cap 1000)")
	cmd.Flags().StringVar(&fCursor, "cursor", "", "pagination cursor from a prior result")
	cmd.Flags().StringVar(&fSort, "sort", "", `sort fields, e.g. "last_seen:desc" or "port:asc,asset_value:asc" (default: last_seen:desc)`)
	cmd.Flags().StringVar(&fMode, "mode", "", "search mode: service (default, one row per service) | asset (one row per asset)")
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
	Facets    bool
	FacetDims []string
	MaxValues int
	Explain   bool
	Validate  bool
	Timeout   time.Duration
	Fields    []string
	Collapse  bool
}

// searchFlagsReset is the test seam that clears the sticky search flag
// values (cobra flags persist on the shared RootCmd between Execute
// calls).  It is a no-op in production; tests call it between
// invocations that set --facet/--facets/--max-values/--collapse so a
// later `search` in the same test binary does not inherit them.
var searchFlagsReset = func() {}

func runSearch(cmd *cobra.Command, args []string, sf searchFlags) error {
	out := cmd.OutOrStdout()
	gql := args[0]

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
	renderSearchWithFacets(out, res, fres, jsonOutput())
	return nil
}

// renderSearchWithFacets renders the result and, when present, the
// facet aggregates (JSON: a facets key; table: a compact section).
func renderSearchWithFacets(out io.Writer, res *search.Result, fres *search.FacetsResult, asJSON bool) {
	if asJSON && fres != nil {
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
		return
	}
	renderResult(out, res, asJSON)
	if fres == nil || asJSON {
		return
	}
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

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

func jsonOutput() bool {
	return flags.output == "json"
}

func renderResult(out io.Writer, res *search.Result, asJSON bool) {
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

	if res.Notice != "" {
		printf(out, "--- %s\n\n", res.Notice)
	}
	printf(out, "%d result(s) in %d ms  (mode=%s)\n", res.Query.RowCount, res.Query.TookMs, res.Query.Mode)
	for _, r := range res.Rows {
		printf(out, "  %s\n", rowLine(r))
	}
	// Small result sets get the full-detail hint; wide tables stay one line.
	if res.HasMore && res.NextCursor != "" {
		printf(out, "\nNext page: append --cursor %s\n", res.NextCursor)
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
// PG-level surprises (unmigrated index) to actionable pointers.
func renderSearchError(out io.Writer, err error) {
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
