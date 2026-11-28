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

package planner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/gql/ast"
)

// planner.go — the M9 GQL → PostgreSQL compiler (SPEC-04 §6, §8).
//
// Compile takes a validated GQL AST (the M7 validator has already
// rewritten aliases to canonical paths and enforced typing/op
// compatibility) and lowers it to a parameterized SQL Plan against
// the search_index union view (migration 0003).
//
// Non-goals (intentionally out of M9 scope):
//   - Execution.  Compile returns SQL + args; the M10 SearchService
//     executes against the pool.
//   - Faceting.  v0.0.1 returns null + a notice (SPEC-03 §3).
//   - ALL semantics.  The M7 validator rejects ALL in v0.0.1; the
//     planner never sees it.
//
// Hard contract (AC-2.8): values are $N placeholders, never
// interpolated into the SQL string.  This is checked by unit tests
// that scan the rendered SQL for any of the literal values.

// Mode is the search mode (PD-1; default service).
type Mode int

const (
	// ModeService returns one row per (asset, service) pair plus orphan
	// assets — the raw search_index projection.
	ModeService Mode = iota

	// ModeAsset collapses to one row per asset (DISTINCT ON asset_id,
	// preferring the row with the most recent last_seen).
	ModeAsset
)

// String renders the canonical mode name (used in EXPLAIN).
func (m Mode) String() string {
	if m == ModeAsset {
		return "asset"
	}
	return "service"
}

// ParseMode parses "service" / "asset" (case-insensitive).
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "service":
		return ModeService, nil
	case "asset":
		return ModeAsset, nil
	}
	return 0, &Error{
		Code:   CodePlanMode,
		Detail: fmt.Sprintf("unknown search mode %q", s),
		Why:    "GSEER ships two modes: service (default, PD-1) and asset",
		Next:   "try: --mode service   or   --mode asset",
	}
}

// Direction is a sort direction.
type Direction int

const (
	// DirAsc sorts ascending; DirDesc sorts descending.
	DirAsc Direction = iota
	DirDesc
)

// String renders the SQL keyword.
func (d Direction) String() string {
	if d == DirDesc {
		return "DESC"
	}
	return "ASC"
}

// ParseDirection parses "asc" / "desc" (case-insensitive).
func ParseDirection(s string) (Direction, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "asc", "ascending":
		return DirAsc, nil
	case "desc", "descending":
		return DirDesc, nil
	}
	return 0, &Error{
		Code:   CodePlanSortDir,
		Detail: fmt.Sprintf("unknown sort direction %q", s),
		Why:    "sort directions are asc and desc",
		Next:   "try: --sort last_seen:desc",
	}
}

// SortSpec is one sort field + direction.
type SortSpec struct {
	Field     string
	Direction Direction
}

// Options controls the compiled Plan.
type Options struct {
	Mode    Mode
	Sort    []SortSpec // empty = default (last_seen DESC, row_id ASC)
	Limit   int        // 0 = server default (DefaultLimit)
	Timeout time.Duration
	Cursor  string // opaque base64 from a prior Result.NextCursor
	Fields  []string
	// Relevance (R114): anchor for substring-family relevance ordering.
	// When Sort is empty and an anchor is supplied, the default ordering
	// becomes relevance ASC, then last_seen DESC; an explicit
	// `relevance` SortSpec requires an anchor.  See relevance.go.
	Relevance *RelevanceAnchor
}

// Defaults and hard caps (PD-1, SPEC-03 §3).
const (
	DefaultLimit = 100
	MaxLimit     = 1000
	MinTimeout   = 100 * time.Millisecond
	MaxTimeout   = 30 * time.Second
)

// Branch classifies the compiled Plan for EXPLAIN output.  A single
// Plan can carry several branches (e.g., a flat predicate wrapped in
// mode=asset AND containing an ANY(host){…} subquery).
type Branch struct {
	Witness    bool // a flat per-row predicate (no quantifier)
	AnyUnion   bool // an ANY(host){…} block compiled to an EXISTS subquery
	AssetAll   bool // mode=asset DISTINCT ON (asset_id) projection
	AnyService bool // an ANY(service){…} block compiled inline (folded to witness)
}

// String renders the active branch set, comma-separated.
func (b Branch) String() string {
	var parts []string
	if b.Witness {
		parts = append(parts, "witness")
	}
	if b.AnyUnion {
		parts = append(parts, "any-union")
	}
	if b.AnyService {
		parts = append(parts, "any-service-inline")
	}
	if b.AssetAll {
		parts = append(parts, "asset-all")
	}
	if len(parts) == 0 {
		return "(none)"
	}
	return strings.Join(parts, " | ")
}

// Plan is the compiled output.
type Plan struct {
	SQL     string
	Args    []any
	Branch  Branch
	Mode    Mode
	Sort    []SortSpec
	Limit   int
	Timeout time.Duration

	// CursorDecoded holds the (sort_key, row_id) decoded from
	// Options.Cursor, for EXPLAIN.  Nil if no cursor was supplied.
	CursorDecoded *CursorPayload

	// ProjectionFields is the field set the SQL projects (after mode
	// collapse if ModeAsset).  Empty = default = all search_index cols.
	ProjectionFields []string

	// Relevance (R114) — carried so the result layer can compute the
	// same tier per row when encoding the pagination cursor.
	Relevance *RelevanceAnchor
}

// CursorPayload is the decoded form of the opaque pagination cursor.
type CursorPayload struct {
	SortField string
	RowID     int64
	// RowKind completes the row key: search_index.row_id is the
	// service id on 'service' rows and the ASSET id on 'asset-only'
	// rows — two independent id sequences that can collide numerically,
	// so (row_kind, row_id) is the true unique row key and the
	// tiebreaker must advance over BOTH.
	RowKind string
	Value   string // stringified sort-key value at the cursor row
	// Null is true when the cursor row's sort value was SQL NULL (the
	// value is "").  NULL rows sort at the ASC-tail / DESC-head (NULLS
	// LAST / NULLS FIRST), so the advancement predicate needs the
	// NULL-aware forms in renderCursorPredicate.
	Null bool
}

// Encode renders an opaque base64 cursor from a cursor payload.
func (c CursorPayload) Encode() string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

// DecodeCursor parses an opaque base64 cursor.
func DecodeCursor(s string) (*CursorPayload, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, &Error{
			Code:   CodePlanCursor,
			Detail: fmt.Sprintf("cursor is not valid base64: %v", err),
			Why:    "the cursor must come from a prior result's next_cursor",
			Next:   "drop --cursor to start a fresh page",
		}
	}
	var p CursorPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, &Error{
			Code:   CodePlanCursor,
			Detail: fmt.Sprintf("cursor payload is malformed: %v", err),
			Why:    "the cursor schema changed between versions or was truncated",
			Next:   "drop --cursor to start a fresh page",
		}
	}
	return &p, nil
}

// ---------------------------------------------------------------------------
// Field → column mapping (canonical path → search_index column name)
// ---------------------------------------------------------------------------

// searchColumns maps every registry canonical path to its search_index
// column name.  The dot-bearing paths (http.*, tls.*) project to the
// snake_case view columns; the bare paths are 1:1.
var searchColumns = map[string]string{
	"ip":          "ip",
	"asset_value": "asset_value",
	"asset_kind":  "asset_kind",
	"domain":      "domain",
	"hostname":    "hostname",
	"asn":         "asn",
	"asn_org":     "asn_org",
	"geo_country": "geo_country",
	"geo_region":  "geo_region",
	"geo_city":    "geo_city",
	"port":        "port",
	"transport":   "transport",
	"protocol":    "protocol",
	"name":        "name",
	"product":     "product",
	"version":     "version",
	"http.status": "http_status",
	"http.title":  "http_title",
	"http.server": "http_server",
	"tls.version": "tls_version",
	// The 0003 view projects latest_tls's columns WITHOUT a tls_ prefix:
	// cert_subject_cn, cert_issuer_cn, cert_expiry (the tls_version name
	// comes from the latest_tls view itself).  0021 adds cert_serial and
	// cert_sans_dns to the same surface.
	"tls.cert_subject_cn": "cert_subject_cn",
	"tls.cert_issuer_cn":  "cert_issuer_cn",
	"tls.cert_expiry":     "cert_expiry",
	"tls.cert_serial":     "cert_serial",
	"tls.cert_sans_dns":   "cert_sans_dns",
	"tls.cert_not_before": "cert_not_before",
	"ct.log":              "ct_log",
	"ct.entry_type":       "ct_entry_type",
	"ct.subject":          "ct_subject_cn",
	"ct.issuer":           "ct_issuer",
	"ct.not_before":       "ct_not_before",
	"ct.not_after":        "ct_not_after",
	"ct.leaf_sha256":      "ct_leaf_sha256",
	"ct.cert_timestamp":   "ct_cert_timestamp",
	"technologies":        "technologies",
	"sources":             "sources",
	"first_seen":          "first_seen",
	"last_seen":           "last_seen",
	"stale":               "stale",
	// R36 evidence quality + R37 field expansion (0006/0022 + 0007/0023
	// project them into the view).
	"coverage":            "coverage_class",
	"last_observed":       "last_observed",
	"prefix":              "ip_prefix",
	"banner":              "banner",
	"tls.cert_issuer_org": "cert_issuer_org",
	"http.headers":        "http_headers",
	"evidence":            "evidence_kinds",
}

// sortableFields is the set of fields the planner allows in ORDER BY.
// List/bool fields are excluded (no meaningful ordering); the rest
// mirror searchColumns.
var sortableFields = map[string]bool{
	"relevance": true, // R114: rank over the anchor predicate's tiers
	"ip":        true, "asset_value": true, "asset_kind": true,
	"domain": true, "hostname": true, "asn": true, "asn_org": true,
	"geo_country": true, "geo_region": true, "geo_city": true,
	"port": true, "transport": true, "protocol": true,
	"name": true, "product": true, "version": true,
	"http.status": true, "http.title": true, "http.server": true,
	"tls.version": true, "tls.cert_subject_cn": true, "tls.cert_issuer_cn": true,
	"tls.cert_expiry": true, "tls.cert_serial": true, "tls.cert_sans_dns": true,
	"tls.cert_not_before": true,
	"first_seen":          true, "last_seen": true,
	"coverage": true, "last_observed": true, "prefix": true,
	"banner": true, "tls.cert_issuer_org": true,
	"ct.not_before": true, "ct.not_after": true, "ct.cert_timestamp": true,
}

// allSearchColumns is the canonical projection list, in view order
// (migration 0003, extended by 0021).  Used when Options.Fields is empty.
var allSearchColumns = []string{
	"row_id", "row_kind",
	"asset_id", "asset_kind", "asset_value",
	"ip", "domain", "hostname", "asn", "asn_org",
	"geo_country", "geo_region", "geo_city",
	"port", "transport", "protocol", "name", "product", "version",
	"http_status", "http_title", "http_server",
	"tls_version", "cert_subject_cn", "cert_issuer_cn", "cert_expiry",
	"cert_serial", "cert_sans_dns", "cert_not_before",
	"technologies", "sources", "first_seen", "last_seen", "stale",
	"evidence_kinds", "last_observed", "coverage_class",
	"http_headers", "cert_issuer_org", "banner", "ip_prefix",
	"ct_log", "ct_entry_type", "ct_subject_cn", "ct_issuer",
	"ct_not_before", "ct_not_after", "ct_leaf_sha256", "ct_cert_timestamp",
	"dns_record",
}

// columnName resolves a canonical path to its search_index column.
// Returns "" if unknown (the validator should have caught this; the
// planner still defends in depth).
func columnName(canonical string) string {
	if c, ok := searchColumns[canonical]; ok {
		return c
	}
	return ""
}

// resolveProjectionColumn accepts either a canonical path (e.g.
// "http.title") or its column name directly (e.g. "http_title"), so
// callers can pass whichever form they hold.  Returns "" if the name
// matches neither form.
func resolveProjectionColumn(name string) string {
	if c := columnName(name); c != "" {
		return c
	}
	// name might already be a column — check membership directly.
	for _, col := range searchColumns {
		if col == name {
			return col
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Compile entry point
// ---------------------------------------------------------------------------

// Compile lowers a validated AST to a parameterized SQL Plan.
//
// Pre-condition: root has been through validator.Validate, so field
// paths are canonical, types match, ops are allowed.  Compile does not
// re-validate semantics; it does check the planner-specific options
// (sort field, mode, limit, timeout, cursor shape).
// compileOptions validates the planner-specific options and applies the
// defaults (limit, timeout, sort).  row_id is ALWAYS appended as the ASC
// tiebreaker (renderSort handles that), so the user-visible sorts must
// not include row_id.
func compileOptions(opts Options) (limit int, timeout time.Duration, sorts []SortSpec, err error) {
	if opts.Limit < 0 || opts.Limit > MaxLimit {
		return 0, 0, nil, &Error{
			Code:   CodePlanLimit,
			Detail: fmt.Sprintf("limit %d is out of range (0–%d)", opts.Limit, MaxLimit),
			Why:    "0 means the server default; the hard cap protects the API",
			Next:   fmt.Sprintf("try: --limit %d", DefaultLimit),
		}
	}
	limit = opts.Limit
	if limit == 0 {
		limit = DefaultLimit
	}

	if opts.Timeout > 0 && (opts.Timeout < MinTimeout || opts.Timeout > MaxTimeout) {
		return 0, 0, nil, &Error{
			Code:   CodePlanTimeout,
			Detail: fmt.Sprintf("timeout %s is out of range (%s–%s)", opts.Timeout, MinTimeout, MaxTimeout),
			Why:    "PD-1 hard cap is 30s; sub-100ms timeouts are not useful at PG round-trip",
			Next:   "try: --timeout 5s",
		}
	}
	timeout = opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	// Normalize sort.  Empty = default: last_seen DESC — or relevance
	// ASC when an R114 anchor is present (exact > prefix > substring
	// within the same matched set).  The ONLY secondary keys are the
	// composite row key: the pagination cursor compares (tier, row_id,
	// row_kind), so any other tiebreaker would make pages skip or
	// repeat rows (the same contract as the coverage rank).
	sorts = opts.Sort
	if len(sorts) == 0 {
		if opts.Relevance != nil {
			sorts = []SortSpec{{Field: "relevance", Direction: DirAsc}}
		} else {
			sorts = []SortSpec{{Field: "last_seen", Direction: DirDesc}}
		}
	}
	for _, s := range sorts {
		if !sortableFields[s.Field] {
			return 0, 0, nil, &Error{
				Code:   CodePlanSortField,
				Detail: fmt.Sprintf("field %q is not sortable", s.Field),
				Why:    "list and bool fields have no meaningful ordering; row_id and the witness fields are sortable",
				Next:   "try: --sort last_seen:desc",
			}
		}
		if s.Field == "relevance" && opts.Relevance == nil {
			return 0, 0, nil, &Error{
				Code:   CodePlanSortField,
				Detail: `sort "relevance" requires a text-match query`,
				Why:    "the relevance rank is derived from a single substring-family predicate (CONTAINS, *=, IN_DOMAIN); this query has none",
				Next:   `try: product CONTAINS "nginx" --sort relevance:asc`,
			}
		}
	}
	return limit, timeout, sorts, nil
}

// resolveProjection maps the requested fields onto search_index columns.
// Accept canonical paths (e.g. "http.title"), their column-name spelling
// ("http_title"), or the row_id / row_kind / asset_id bookkeeping
// columns that the registry does not surface.  Empty = all columns.
func resolveProjection(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return allSearchColumns, nil
	}
	resolved := make([]string, 0, len(fields))
	for _, f := range fields {
		col := resolveProjectionColumn(f)
		if col == "" {
			// Allow the bookkeeping columns the registry omits.
			switch f {
			case "row_id", "row_kind", "asset_id":
				col = f
			default:
				return nil, &Error{
					Code:   CodePlanProjection,
					Detail: fmt.Sprintf("projection field %q is not a search_index column", f),
					Why:    "the planner projects only canonical search_index columns",
					Next:   "see the field registry: gseer search --help",
				}
			}
		}
		resolved = append(resolved, col)
	}
	return resolved, nil
}

// decodeCursorForSort decodes the page cursor (if any) and validates it
// matches the first sort field (a cursor is tied to the sort order of
// the page that produced it).
func decodeCursorForSort(cursor string, sorts []SortSpec) (*CursorPayload, error) {
	if cursor == "" {
		return nil, nil
	}
	cp, err := DecodeCursor(cursor)
	if err != nil {
		return nil, err
	}
	if cp != nil && cp.SortField != sorts[0].Field {
		return nil, &Error{
			Code:   CodePlanCursor,
			Detail: fmt.Sprintf("cursor was for sort field %q; current sort starts with %q", cp.SortField, sorts[0].Field),
			Why:    "a cursor is tied to the sort order of the page that produced it",
			Next:   "drop --cursor to start a fresh page, or restore the matching --sort",
		}
	}
	return cp, nil
}

// composeSelect renders the final SELECT.  ModeAsset wraps the body in a
// DISTINCT ON (asset_id) subquery that prefers the most-recent-last_seen
// row; service mode queries search_index directly with the cursor
// ANDed into the inner WHERE (keyset pagination over raw rows).
func composeSelect(mode Mode, projection []string, sorts []SortSpec, whereSQL, whereSQLNoCursor, curPred, sortClause string, limitIdx int) string {
	// For mode=asset the inner CTE projection MUST include asset_id and
	// last_seen even if the caller did not ask for them — the outer
	// DISTINCT ON (asset_id) and ORDER BY last_seen DESC depend on them.
	projCols := strings.Join(quoteIdentList(projection), ", ")

	var sql strings.Builder
	if mode == ModeAsset {
		// Asset mode: dedup FIRST, then cursor/ORDER/LIMIT on the
		// deduped set.  (Paginating the raw rows and deduping per page
		// would split one asset across pages and produce uneven page
		// sizes — the cursor must advance over DISTINCT ASSETS.)
		//
		//   page CTE: DISTINCT ON (asset_id) keeps each asset's
		//     representative row (max last_seen, then max row_id);
		//     no LIMIT here — the limit applies to the deduped set.
		//   outer: cursor predicate + user sort + LIMIT.
		innerProj := append([]string{}, projection...)
		for _, required := range []string{"asset_id", "row_id", "row_kind", "last_seen"} {
			if !containsString(innerProj, required) {
				innerProj = append(innerProj, required)
			}
		}
		for _, s := range sorts {
			col := columnName(s.Field)
			if col != "" && !containsString(innerProj, col) {
				innerProj = append(innerProj, col)
			}
		}
		innerCols := strings.Join(quoteIdentList(innerProj), ", ")
		sql.WriteString("WITH page AS (\n")
		sql.WriteString("  SELECT DISTINCT ON (asset_id) " + innerCols + " FROM search_index\n")
		sql.WriteString("  WHERE " + whereSQLNoCursor + "\n")
		sql.WriteString("  ORDER BY asset_id, last_seen DESC NULLS LAST, row_id ASC\n")
		sql.WriteString(")\n")
		sql.WriteString("SELECT " + projCols + " FROM page\n")
		if curPred != "" {
			// The cursor predicate renders unqualified column names, so
			// it binds to the page CTE's output columns here.
			sql.WriteString("WHERE " + curPred + "\n")
		}
		sql.WriteString("ORDER BY " + sortClause + "\n")
		sql.WriteString("LIMIT $" + fmt.Sprintf("%d", limitIdx) + "\n")
	} else {
		sql.WriteString("SELECT " + projCols + " FROM search_index\n")
		sql.WriteString("WHERE " + whereSQL + "\n")
		if sortClause != "" {
			sql.WriteString("ORDER BY " + sortClause + "\n")
		}
		sql.WriteString("LIMIT $" + fmt.Sprintf("%d", limitIdx) + "\n")
	}
	return sql.String()
}

func Compile(root ast.Node, opts Options) (*Plan, error) {
	if root == nil {
		return nil, &Error{
			Code:   CodePlanEmpty,
			Detail: "no query to compile",
			Why:    "Compile was called with a nil AST root",
			Next:   "supply a parsed-and-validated GQL expression",
		}
	}

	limit, timeout, sorts, err := compileOptions(opts)
	if err != nil {
		return nil, err
	}

	projection, err := resolveProjection(opts.Fields)
	if err != nil {
		return nil, err
	}

	// Decode cursor (if any) and validate it matches the first sort field.
	cursorPayload, err := decodeCursorForSort(opts.Cursor, sorts)
	if err != nil {
		return nil, err
	}

	// Compile the WHERE clause.  b.args accumulates the positional
	// placeholder values ($1, $2, …); the next placeholder index is
	// len(b.args)+1.
	b := &builder{}
	branch := Branch{}
	whereSQL := b.compileNode(root, "search_index", &branch)
	if !branch.Witness && !branch.AnyUnion && !branch.AnyService {
		// The root was a leaf — implicit witness.
		branch.Witness = true
	}

	// Cursor predicate — rendered ONCE here (before the args copy) so
	// its two placeholders join the shared args vector.  Placement
	// differs by mode:
	//   service mode: ANDed into the inner WHERE (keyset over raw rows);
	//   asset mode:   applied on the deduped page CTE (keyset over
	//                 distinct assets).
	var curPred string
	if cursorPayload != nil {
		curPred = b.renderCursorPredicate(sorts[0], cursorPayload, opts.Relevance)
	}
	whereSQLNoCursor := whereSQL
	if curPred != "" {
		// Service mode keeps the cursor inside the inner WHERE
		// (keyset pagination over raw rows).  Asset mode splices it
		// out again below — the CTE WHERE uses whereSQLNoCursor.
		whereSQL = "(" + whereSQL + " AND " + curPred + ")"
	}

	// ORDER BY clause.  R114: the relevance rank's $N placeholders are
	// bound here — they append to b.args AFTER the WHERE/cursor args
	// (matching their position in the SQL text) and BEFORE the limit
	// placeholder computed just below.
	sortClause := renderSort(sorts, b, opts.Relevance)

	// Limit placeholder.
	args := append([]any{}, b.args...)
	limitIdx := len(args) + 1
	args = append(args, limit)

	// Per-query timeout: kept on the Plan as a Go duration; the M10
	// SearchService applies it via `SELECT set_config('statement_timeout',
	// $N::text, true)` in the same transaction before running the
	// SELECT.  We deliberately do NOT bake it into Plan.SQL: (a) PG's
	// `SET LOCAL` does not accept a $N placeholder, so embedding it
	// would force interpolation (AC-2.8 violation); (b) `set_config`
	// is a SELECT that returns a row, which would complicate the result
	// row scanning contract; (c) the timeout is an execution-layer
	// concern, not a plan-shape concern.

	// Compose the SELECT (mode asset wraps the body in a DISTINCT ON
	// subquery — see composeSelect).
	if opts.Mode == ModeAsset {
		branch.AssetAll = true
	}
	sqlStr := composeSelect(opts.Mode, projection, sorts, whereSQL, whereSQLNoCursor, curPred, sortClause, limitIdx)

	return &Plan{
		SQL:              sqlStr,
		Args:             args,
		Branch:           branch,
		Mode:             opts.Mode,
		Sort:             sorts,
		Limit:            limit,
		Timeout:          timeout,
		CursorDecoded:    cursorPayload,
		ProjectionFields: projection,
		Relevance:        opts.Relevance,
	}, nil
}

// CompileWhere compiles a validated AST into ONLY the WHERE clause over
// search_index plus its positional args — no SELECT, ORDER BY, or LIMIT.
// It is the facet engine's entry point (internal/search/facets.go):
// facet aggregates must filter over exactly the rows the search would
// return, so they reuse the planner's WHERE compilation verbatim
// (same operator lowering, same alias qualification, same literal
// handling).  The returned SQL is safe to embed in
// `... FROM search_index WHERE (<where>) ...`.
func CompileWhere(root ast.Node) (where string, args []any, branch Branch, err error) {
	if root == nil {
		return "", nil, Branch{}, &Error{
			Code:   CodePlanEmpty,
			Detail: "no query to compile",
			Why:    "CompileWhere was called with a nil AST root",
			Next:   "supply a parsed-and-validated GQL expression",
		}
	}
	b := &builder{}
	branch = Branch{}
	where = b.compileNode(root, "search_index", &branch)
	if !branch.Witness && !branch.AnyUnion && !branch.AnyService {
		branch.Witness = true
	}
	return where, b.args, branch, nil
}

// ApplyStatementTimeoutSQL returns a parameterized SQL statement that
// applies Plan.Timeout as a transaction-local statement_timeout when
// executed in the same transaction as Plan.SQL.  M10's SearchService
// uses this so the timeout value never appears literally in any SQL
// text (AC-2.8): the value is bound through the args slice.
//
// The returned (sql, args) pair is `SELECT set_config('statement_timeout',
// $1::text, true)` with the timeout in milliseconds as a string.  PG's
// `SET LOCAL` does not accept a $N placeholder, so set_config() is the
// parameterized form.  Returns ("", nil) when the plan has no timeout.
func (p *Plan) ApplyStatementTimeoutSQL() (string, []any) {
	if p == nil || p.Timeout <= 0 {
		return "", nil
	}
	ms := int64(p.Timeout / time.Millisecond)
	return `SELECT set_config('statement_timeout', $1::text, true)`, []any{fmt.Sprintf("%d", ms)}
}

// quoteIdentList quotes each column as "col" for SQL safety.
func quoteIdentList(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = `"` + strings.ReplaceAll(c, `"`, `""`) + `"`
	}
	return out
}

// containsString reports whether s is in slice.  Used by the mode=asset
// projection composition to avoid duplicate columns.
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// builder — recursive WHERE-clause compiler
// ---------------------------------------------------------------------------

type builder struct {
	args []any
}

// compileNode returns a SQL fragment expressing the node's predicate.
// alias is the SQL alias for search_index at this level of the
// recursion (so subqueries can re-bind).  branch accumulates which
// projection branches are exercised, for EXPLAIN.
func (b *builder) compileNode(n ast.Node, alias string, branch *Branch) string {
	switch t := n.(type) {
	case *ast.Or:
		l := b.compileNode(t.L, alias, branch)
		r := b.compileNode(t.R, alias, branch)
		return "(" + l + " OR " + r + ")"
	case *ast.And:
		l := b.compileNode(t.L, alias, branch)
		r := b.compileNode(t.R, alias, branch)
		return "(" + l + " AND " + r + ")"
	case *ast.Not:
		x := b.compileNode(t.X, alias, branch)
		return "(NOT (" + x + "))"
	case *ast.Comparison:
		return b.compileComparison(t, alias, branch)
	case *ast.Exists:
		col := columnName(t.Field)
		if col == "" {
			col = t.Field // validator should have caught this; defend in depth
		}
		branch.Witness = true
		return fmt.Sprintf("%s.\"%s\" IS NOT NULL", alias, col)
	case *ast.Quantified:
		return b.compileQuantified(t, alias, branch)
	case *ast.FreeText:
		return b.compileFreeText(t, alias)
	}
	return "TRUE"
}

// compileComparison lowers one field/op/value triple.
func (b *builder) compileComparison(c *ast.Comparison, alias string, branch *Branch) string {
	// Derived compatibility fields have no search_index column; the
	// planner lowers them to predicates over the underlying columns.
	if sql, ok := b.compileDerived(c, alias); ok {
		return sql
	}
	if sql, ok := b.compileHostOrIP(c, alias); ok {
		return sql
	}
	// R37 dynamic per-name header fields (http.header.<name> and the
	// http.headers.<name> alias form) lower to a jsonb key extraction
	// over the captured headers object; the name is validator-charset
	// checked ([a-z0-9_-]+), so the single-quoted literal is safe.
	if name, ok := dynamicHeaderKey(c.Field); ok {
		branch.Witness = true
		return b.compileColumnOps(fmt.Sprintf(`%s."http_headers" ->> '%s'`, alias, name), c)
	}
	// R39 P4 dynamic dns.<key> fields lower to a jsonb key extraction
	// over the latest_dns projection (dns_record).
	if name, ok := dynamicDNSKey(c.Field); ok {
		branch.Witness = true
		return b.compileColumnOps(fmt.Sprintf(`%s."dns_record" ->> '%s'`, alias, name), c)
	}
	col := columnName(c.Field)
	if col == "" {
		col = c.Field
	}
	branch.Witness = true
	qcol := alias + ".\"" + col + "\""

	return b.compileColumnOps(qcol, c)
}

// dynamicHeaderKey splits a canonical dynamic header field into its
// validated key part ("http.headers.x-powered-by" → "x-powered-by").
// The static bare "http.headers" is NOT dynamic — it maps to the
// http_headers column through searchColumns.
func dynamicHeaderKey(canonical string) (string, bool) {
	rest, ok := strings.CutPrefix(canonical, "http.headers.")
	if !ok || rest == "" {
		return "", false
	}
	return rest, true
}

// dynamicDNSKey splits a canonical dynamic dns field into its validated
// key part ("dns.type" → "type") — R39 P4.
func dynamicDNSKey(canonical string) (string, bool) {
	rest, ok := strings.CutPrefix(canonical, "dns.")
	if !ok || rest == "" {
		return "", false
	}
	return rest, true
}

func (b *builder) compileColumnOps(qcol string, c *ast.Comparison) string {
	switch c.Op {
	case ast.OpEq, ast.OpNeq, ast.OpLt, ast.OpLe, ast.OpGt, ast.OpGe:
		op := opSQL(c.Op)
		// Compatibility empty-value semantics: `field=""` matches rows
		// where the field is missing OR empty; `field!=""` matches rows
		// where the field is present AND non-empty.
		if sv, isEmpty := c.Value.(*ast.StrValue); isEmpty && sv.S == "" {
			if c.Op == ast.OpEq {
				return fmt.Sprintf("(%s IS NULL OR %s = '')", qcol, qcol)
			}
			return fmt.Sprintf("(%s IS NOT NULL AND %s <> '')", qcol, qcol)
		}
		return b.simpleCompare(qcol, op, c.Value)
	case ast.OpIn:
		return b.compileIn(qcol, c.Value)
	case ast.OpContains:
		return b.compileContains(qcol, c.Value, c.Field)
	case ast.OpInCidr:
		return b.compileInCidr(qcol, c.Value)
	case ast.OpInDomain:
		return b.compileInDomain(qcol, c.Value)
	case ast.OpMatch:
		// The ip column is inet-typed in the view; ILIKE needs
		// text, and host(inet) strips the trailing /32 (or /128)
		// prefix that ip::text would keep — otherwise a
		// suffix-anchored pattern like "*.10" can never match.
		if c.Field == "ip" {
			qcol = fmt.Sprintf("host(%s)", qcol)
		}
		return b.compileMatch(qcol, c.Value)
	}
	return "TRUE"
}

// compileDerived lowers the compatibility boolean fields (is_domain,
// is_ipv6, cert.is_expired) to predicates over the underlying
// search_index columns.  The second result is false when the node is
// not a derived-field comparison (the caller falls through to the
// normal column path).
func (b *builder) compileDerived(c *ast.Comparison, alias string) (string, bool) {
	want, ok := boolValue(c.Value)
	if !ok {
		return "", false // validator rejects non-bool for TypeBool fields
	}
	colOf := func(field string) string {
		name := columnName(field)
		if name == "" {
			name = field
		}
		return alias + ".\"" + name + "\""
	}
	switch c.Field {
	case "is_domain":
		d := colOf("domain")
		if want {
			return fmt.Sprintf("(%s IS NOT NULL AND %s <> '')", d, d), true
		}
		return fmt.Sprintf("(%s IS NULL OR %s = '')", d, d), true
	case "is_ipv6":
		ip := colOf("ip") + "::text" // the ip column is inet-typed
		if want {
			return fmt.Sprintf("(%s IS NOT NULL AND position(':' in %s) > 0)", ip, ip), true
		}
		return fmt.Sprintf("(%s IS NOT NULL AND position(':' in %s) = 0)", ip, ip), true
	case "cert.is_expired":
		e := colOf("tls.cert_expiry")
		if want {
			return fmt.Sprintf("(%s IS NOT NULL AND %s < now())", e, e), true
		}
		return fmt.Sprintf("(%s IS NOT NULL AND %s >= now())", e, e), true
	}
	return "", false
}

// compileHostOrIP lowers the compatibility field host_or_ip (the user
// alias `host`): a match over BOTH the hostname and the ip columns,
// so `host="portal.example"` and `host="203.0.113.10"` both resolve.
// The empty value keeps the hostname presence semantics (`host=""` =
// no hostname).  The second result is false when the node is not a
// host_or_ip comparison (the caller falls through to the normal
// column path).
func (b *builder) compileHostOrIP(c *ast.Comparison, alias string) (string, bool) {
	if c.Field != "host_or_ip" {
		return "", false
	}
	h := alias + `."hostname"`
	// host(inet) renders the bare address WITHOUT the /32 (or /128)
	// prefix netmask that ip::text keeps, so text equality against a
	// user-written address matches.
	i := fmt.Sprintf("host(%s.\"ip\")", alias)
	or2 := func(a, b2 string) string { return "(" + a + " OR " + b2 + ")" }
	switch c.Op {
	case ast.OpEq, ast.OpNeq:
		op := opSQL(c.Op)
		if sv, isEmpty := c.Value.(*ast.StrValue); isEmpty && sv.S == "" {
			if c.Op == ast.OpEq {
				return fmt.Sprintf("(%s IS NULL OR %s = '')", h, h), true
			}
			return fmt.Sprintf("(%s IS NOT NULL AND %s <> '')", h, h), true
		}
		return or2(b.simpleCompare(h, op, c.Value), b.simpleCompare(i, op, c.Value)), true
	case ast.OpMatch:
		return or2(b.compileMatch(h, c.Value), b.compileMatch(i, c.Value)), true
	case ast.OpContains:
		return or2(b.compileContains(h, c.Value, c.Field), b.compileContains(i, c.Value, c.Field)), true
	case ast.OpIn:
		return or2(b.compileIn(h, c.Value), b.compileIn(i, c.Value)), true
	}
	return "", false
}

// boolValue extracts a validated boolean literal ("true"/"false").
func boolValue(v ast.Value) (bool, bool) {
	if bv, ok := v.(*ast.BoolValue); ok {
		return bv.B, true
	}
	sv, ok := v.(*ast.StrValue)
	if !ok {
		return false, false
	}
	switch sv.S {
	case "true":
		return true, true
	case "false":
		return false, true
	}
	return false, false
}

// compileMatch lowers `field *= "pattern"` to a case-insensitive
// wildcard ILIKE: `*` matches any run of characters, `?` matches
// exactly one; every other rune — including the SQL LIKE
// metacharacters %, _ and the escape character — is matched
// literally.
func (b *builder) compileMatch(qcol string, v ast.Value) string {
	sv, ok := v.(*ast.StrValue)
	if !ok {
		return "FALSE"
	}
	idx := b.placeholder(matchPattern(sv.S))
	return fmt.Sprintf("%s ILIKE $%d ESCAPE '\\'", qcol, idx)
}

// matchPattern translates a user wildcard pattern into a SQL LIKE
// pattern with backslash-escaped literals.
func matchPattern(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch r {
		case '\\':
			out.WriteString(`\\`)
		case '%':
			out.WriteString("\\%")
		case '_':
			out.WriteString("\\_")
		case '*':
			out.WriteRune('%')
		case '?':
			out.WriteRune('_')
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// compileFreeText defensively lowers the free-text node (the
// validator normally expands it into comparisons before planning;
// the planner stays self-contained when invoked without the
// validator).  Semantics match the validator expansion: OR across
// the free-text columns per term, AND across terms.
func (b *builder) compileFreeText(ft *ast.FreeText, alias string) string {
	var out string
	for i, term := range ft.Terms {
		var termSQL string
		for j, field := range freeTextFieldPaths {
			name := columnName(field)
			if name == "" {
				name = field
			}
			qcol := alias + ".\"" + name + "\""
			frag := b.compileContains(qcol, &ast.StrValue{S: term}, field)
			if j == 0 {
				termSQL = frag
			} else {
				termSQL = "(" + termSQL + " OR " + frag + ")"
			}
		}
		if i == 0 {
			out = termSQL
		} else {
			out = "(" + out + " AND " + termSQL + ")"
		}
	}
	return out
}

// freeTextFieldPaths mirrors validator.FreeTextFields (the planner
// must not import the validator; TestFreeTextFieldListsMatch pins
// the two lists together).
var freeTextFieldPaths = []string{
	"asset_value",
	"hostname",
	"domain",
	"http.title",
	"http.server",
	"product",
	"name",
	"asn_org",
	"tls.cert_subject_cn",
	"tls.cert_issuer_cn",
}

// opSQL maps an ast.Op to its SQL comparator spelling.
func opSQL(op ast.Op) string {
	switch op {
	case ast.OpEq:
		return "="
	case ast.OpNeq:
		return "<>"
	case ast.OpLt:
		return "<"
	case ast.OpLe:
		return "<="
	case ast.OpGt:
		return ">"
	case ast.OpGe:
		return ">="
	}
	return "?"
}

// simpleCompare handles =, <>, <, <=, >, >= against a scalar value.
func (b *builder) simpleCompare(qcol, op string, v ast.Value) string {
	switch val := v.(type) {
	case *ast.StrValue:
		idx := b.placeholder(val.S)
		return fmt.Sprintf("%s %s $%d", qcol, op, idx)
	case *ast.IntValue:
		idx := b.placeholder(val.N)
		return fmt.Sprintf("%s %s $%d", qcol, op, idx)
	case *ast.ListValue:
		// Should not happen for non-IN ops; the validator rejects it.
		// Fall back to OR-chaining.
		var parts []string
		for _, item := range val.Items {
			parts = append(parts, b.simpleCompare(qcol, op, item))
		}
		return "(" + strings.Join(parts, " OR ") + ")"
	}
	return "TRUE"
}

// compileIn lowers `field IN (a, b, …)` to `field = ANY($N::T[])`.
func (b *builder) compileIn(qcol string, v ast.Value) string {
	list, ok := v.(*ast.ListValue)
	if !ok {
		// Single-value IN: treat as equality.
		return b.simpleCompare(qcol, "=", v)
	}
	if len(list.Items) == 0 {
		return "FALSE"
	}
	// Determine the array element type from the first item.
	first := list.Items[0]
	var arr any
	switch first.(type) {
	case *ast.StrValue:
		strs := make([]string, 0, len(list.Items))
		for _, it := range list.Items {
			if sv, ok := it.(*ast.StrValue); ok {
				strs = append(strs, sv.S)
			}
		}
		arr = strs
		idx := b.placeholder(arr)
		return fmt.Sprintf("%s = ANY($%d::text[])", qcol, idx)
	case *ast.IntValue:
		ints := make([]int64, 0, len(list.Items))
		for _, it := range list.Items {
			if iv, ok := it.(*ast.IntValue); ok {
				ints = append(ints, iv.N)
			}
		}
		arr = ints
		idx := b.placeholder(arr)
		return fmt.Sprintf("%s = ANY($%d::bigint[])", qcol, idx)
	}
	return "FALSE"
}

// compileContains lowers `field CONTAINS value`:
//   - for list-typed fields (technologies, sources): `field @> ARRAY[$N]::T[]`
//   - for string-typed fields: case-insensitive substring `ILIKE '%' || $N || '%'`
//
// The registry's field type drives the choice; we re-derive it from
// the canonical field name to keep the planner self-contained (the
// validator is the canonical source, but the planner must still lower
// correctly even if invoked outside the validator).
func (b *builder) compileContains(qcol string, v ast.Value, canonicalField string) string {
	if canonicalField == "evidence" {
		// evidence_kinds is jsonb (0022): jsonb `?` tests top-level
		// string ELEMENTS of an array — exact family membership, not a
		// substring guess.
		if sv, ok := v.(*ast.StrValue); ok {
			return fmt.Sprintf("%s ? $%d", qcol, b.placeholder(sv.S))
		}
		return "FALSE"
	}
	if isListField(canonicalField) {
		// Element membership.  GQL CONTAINS on a list takes one value;
		// element typing mirrors the field (text[] for v0.0.1).
		if sv, ok := v.(*ast.StrValue); ok {
			idx := b.placeholder(sv.S)
			return fmt.Sprintf("%s @> ARRAY[$%d]::text[]", qcol, idx)
		}
		if iv, ok := v.(*ast.IntValue); ok {
			idx := b.placeholder(iv.N)
			return fmt.Sprintf("%s @> ARRAY[$%d]::bigint[]", qcol, idx)
		}
		return "FALSE"
	}
	// String substring (case-insensitive per the GQL spec).
	if sv, ok := v.(*ast.StrValue); ok {
		idx := b.placeholder("%" + likeEscape(sv.S) + "%")
		return fmt.Sprintf("%s ILIKE $%d ESCAPE '\\'", qcol, idx)
	}
	return "FALSE"
}

// compileInCidr lowers `ip IN_CIDR "10.0.0.0/8"` to
// `ip::inet <<= $N::cidr`.  `<<=` is "contained in or equal to".
// The ip column is text; the cast is safe because the validator
// checks the value parses as an inet (TODO M9.1: add CIDR-shape check
// in the validator; for now the planner relies on PG's cast error).
func (b *builder) compileInCidr(qcol string, v ast.Value) string {
	if sv, ok := v.(*ast.StrValue); ok {
		idx := b.placeholder(sv.S)
		return fmt.Sprintf("%s::inet <<= $%d::cidr", qcol, idx)
	}
	return "FALSE"
}

// compileInDomain lowers `domain IN_DOMAIN "example.com"` to
// `domain = $N OR domain ILIKE '%.' || $N`.  The OR-form matches the
// domain itself and any subdomain.
func (b *builder) compileInDomain(qcol string, v ast.Value) string {
	if sv, ok := v.(*ast.StrValue); ok {
		idx := b.placeholder(sv.S)
		patIdx := b.placeholder("%." + likeEscape(sv.S))
		return fmt.Sprintf("(%s = $%d OR %s ILIKE $%d ESCAPE '\\')", qcol, idx, qcol, patIdx)
	}
	return "FALSE"
}

// compileQuantified lowers ANY(host){ body } and ANY(service){ body }.
//   - ANY(service): the search_index row IS the service; the body
//     compiles inline against the current alias (folded to witness).
//   - ANY(host): the host (asset + its services) satisfies the body
//     if there EXISTS a service-granular search_index row of the same
//     asset_id whose body holds.  This becomes a correlated EXISTS
//     subquery against a fresh alias.
func (b *builder) compileQuantified(q *ast.Quantified, alias string, branch *Branch) string {
	scope := strings.ToLower(q.Field)
	switch scope {
	case "service":
		branch.AnyService = true
		branch.Witness = true
		return b.compileNode(q.Body, alias, branch)
	case "host":
		branch.AnyUnion = true
		innerAlias := "host_row"
		inner := b.compileNode(q.Body, innerAlias, branch)
		return fmt.Sprintf(
			"EXISTS (SELECT 1 FROM search_index %s WHERE %s.asset_id = %s.asset_id AND %s.row_kind = 'service' AND %s)",
			innerAlias, innerAlias, alias, innerAlias, inner,
		)
	}
	// Validator should have rejected this; defend in depth.
	return "FALSE"
}

// placeholder appends v to the args list and returns its 1-based index.
func (b *builder) placeholder(v any) int {
	b.args = append(b.args, v)
	return len(b.args)
}

// renderSort emits the ORDER BY clause.  No placeholders.  NULLS LAST
// for ASC and NULLS FIRST for DESC: stale/empty values never dominate
// the first page of either direction.  The deterministic tiebreaker is
// the composite row key: row_id ASC then row_kind ASC — row_id alone is
// NOT unique across the union view (services.id on 'service' rows,
// assets.id on 'asset-only' rows are independent sequences that can
// collide numerically), so pagination must advance over both columns.
// renderSort renders the ORDER BY clause.  R114: the relevance field
// expands to the anchor's tier CASE whose $N placeholders bind through
// b — AFTER the WHERE/cursor args (matching SQL text order), BEFORE
// the limit placeholder.
func renderSort(sorts []SortSpec, b *builder, rel *RelevanceAnchor) string {
	parts := make([]string, 0, len(sorts)+2)
	for _, s := range sorts {
		col := columnName(s.Field)
		if col == "" {
			col = s.Field
		}
		nulls := "NULLS LAST"
		if s.Direction == DirDesc {
			nulls = "NULLS FIRST"
		}
		expr := fmt.Sprintf("\"%s\"", col)
		if col == "coverage_class" {
			expr = coverageRankExpr(expr)
		}
		if s.Field == "relevance" {
			expr = relevanceRankExpr(b, rel)
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", expr, s.Direction.String(), nulls))
	}
	parts = append(parts, `"row_id" ASC NULLS LAST`, `"row_kind" ASC`)
	return strings.Join(parts, ", ")
}

// relevanceRankExpr renders the R114 tier CASE for the anchor's
// predicate family.  Tier 0 = exact (case-insensitive via lower()),
// tier 1 = prefix (CONTAINS only), tier 2 = the rest of the matched
// set.  The numbers stay in lockstep with RelevanceAnchor.Tier — the
// cursor payload carries the tier, and page 2 compares it against this
// same expression.  PG spells the case-insensitive exact match with
// lower() (view columns use non-C collations; no COLLATE clause).
func relevanceRankExpr(b *builder, rel *RelevanceAnchor) string {
	if rel == nil {
		return "0"
	}
	col := columnName(rel.Field)
	if col == "" {
		col = rel.Field
	}
	qcol := `"` + col + `"`
	switch rel.Kind {
	case RelContains:
		eqIdx := b.placeholder(rel.Value)
		preIdx := b.placeholder(likeEscape(rel.Value) + "%")
		return fmt.Sprintf(`CASE WHEN lower(%s) = lower($%d) THEN 0
			 WHEN %s ILIKE $%d ESCAPE '\' THEN 1
			 ELSE 2 END`, qcol, eqIdx, qcol, preIdx)
	case RelMatch:
		eqIdx := b.placeholder(rel.Core)
		return fmt.Sprintf(`CASE WHEN lower(%s) = lower($%d) THEN 0 ELSE 1 END`, qcol, eqIdx)
	case RelInDomain:
		eqIdx := b.placeholder(rel.Value)
		return fmt.Sprintf(`CASE WHEN lower(%s) = lower($%d) THEN 0 ELSE 1 END`, qcol, eqIdx)
	}
	return "0"
}

// CoverageRank maps a coverage_class value to its declared
// evidence-strength rank (R45): service-observed (6, strongest) down to
// unclassified (0).  This is the single source of truth the SQL CASE in
// coverageRankExpr mirrors — cursor payloads carry this integer, so a
// future class change must update both together (the planner test pins
// the ladder).
func CoverageRank(class string) int64 {
	switch class {
	case "service-observed":
		return 6
	case "tls-observed":
		return 5
	case "http-observed":
		return 4
	case "routing-confirmed":
		return 3
	case "dns-resolved":
		return 2
	case "discovered":
		return 1
	default:
		return 0 // unclassified and anything unrecognized
	}
}

// coverageRankExpr renders the evidence-strength ORDER BY expression for
// the coverage field (R45).  The coverage_class values are ordered by the
// strongest-evidence-wins rule the 0006/0022 derivation defines:
// service-observed > tls-observed > http-observed > routing-confirmed >
// dns-resolved > discovered > unclassified.  Sorting by "coverage" uses
// this rank — transparent (visible in --explain), deterministic and
// score-free (a declared mapping, not a fabricated relevance number).
// Anything unrecognized ranks with unclassified (0) so a future class can
// never silently outrank the declared ladder.
func coverageRankExpr(qcol string) string {
	return fmt.Sprintf(`CASE %s
		  WHEN 'service-observed' THEN 6
		  WHEN 'tls-observed' THEN 5
		  WHEN 'http-observed' THEN 4
		  WHEN 'routing-confirmed' THEN 3
		  WHEN 'dns-resolved' THEN 2
		  WHEN 'discovered' THEN 1
		  ELSE 0
		END`, qcol)
}

// renderCursorPredicate emits the strict-advancement predicate for the
// primary sort column.  It is NULL-aware and direction-correct:
//
// With the planner's fixed NULL placement (ASC → NULLS LAST, DESC →
// NULLS FIRST) and the always-ASC row_id tiebreaker, the rows strictly
// after the cursor row are:
//
//	ASC, non-null cursor value v:
//	    col > v  OR  (col = v AND row_id > id)  OR  col IS NULL
//	    (the OR col IS NULL arm is REQUIRED: NULLs sort after every
//	    non-null value, so they belong to the pages after v)
//	ASC, null cursor value (v traversed into the NULL tail):
//	    col IS NULL AND row_id > id
//	    (NULL-to-NULL ordering inside the tail is by row_id)
//	DESC, non-null cursor value v (NULL head already behind us):
//	    col < v  OR  (col = v AND row_id > id)
//	DESC, null cursor value (still inside the NULL head):
//	    (col IS NULL AND row_id > id)  OR  col IS NOT NULL
//
// The value placeholder is cast to the sort column's type (::bigint for
// integer fields, ::timestamptz for timestamp fields, ::text otherwise)
// so the comparison is well-typed regardless of driver type inference.
func (b *builder) renderCursorPredicate(primary SortSpec, cursor *CursorPayload, rel *RelevanceAnchor) string {
	col := columnName(primary.Field)
	if col == "" {
		col = primary.Field
	}
	cast := columnCast(primary.Field)
	qcol := `"` + col + `"`
	if primary.Field == "relevance" && rel != nil {
		// R114: the ORDER BY ranked by the tier CASE; the cursor
		// predicate must compare the SAME expression or pages would
		// skip or repeat rows (same rule as the coverage rank).  Unlike
		// the constant coverage CASE, the tier CASE carries $N
		// placeholders and appears THREE times below — each occurrence
		// binds its own copy, in text order.
		return b.relevanceCursorPredicate(rel, cursor, primary.Direction)
	}
	if col == "coverage_class" {
		// R45: the ORDER BY used the evidence-strength CASE; the cursor
		// predicate must compare the SAME expression or pages would skip
		// or repeat rows.  The cast is dropped for the rank expression —
		// CASE yields an integer already.
		qcol = coverageRankExpr(qcol)
		cast = ""
	}
	idIdx := b.placeholder(cursor.RowID)
	kindIdx := b.placeholder(cursor.RowKind)
	// rowKeyGT is the strict-advancement fragment over the composite row
	// key (row_id, row_kind): the next row after the cursor in the
	// tiebreak order row_id ASC, row_kind ASC.
	rowKeyGT := fmt.Sprintf(
		`(row_id > $%d OR (row_id = $%d AND row_kind > $%d))`,
		idIdx, idIdx, kindIdx,
	)

	if cursor.Null {
		if primary.Direction == DirDesc {
			// NULL head: remaining NULL rows (by row key), then all non-NULL.
			return fmt.Sprintf("((%s IS NULL AND %s) OR %s IS NOT NULL)", qcol, rowKeyGT, qcol)
		}
		// NULL tail: remaining NULL rows ordered by row key.
		return fmt.Sprintf("(%s IS NULL AND %s)", qcol, rowKeyGT)
	}

	valIdx := b.placeholder(cursor.Value)
	if primary.Direction == DirDesc {
		return fmt.Sprintf(
			"(%s < ($%d)%s OR (%s = ($%d)%s AND %s))",
			qcol, valIdx, cast, qcol, valIdx, cast, rowKeyGT,
		)
	}
	return fmt.Sprintf(
		"(%s > ($%d)%s OR (%s = ($%d)%s AND %s) OR %s IS NULL)",
		qcol, valIdx, cast, qcol, valIdx, cast, rowKeyGT, qcol,
	)
}

// relevanceCursorPredicate renders the strict-advancement predicate
// for the relevance tier (R114).  Binding order follows SQL text order:
// occurrence 1 of the tier CASE, the strict-compare value, occurrence
// 2, the tiebreaker-equality value, the composite row key, occurrence
// 3 (the ASC NULL-tail check; the tier is never NULL so it only
// completes the shape).
func (b *builder) relevanceCursorPredicate(rel *RelevanceAnchor, cursor *CursorPayload, dir Direction) string {
	c1 := relevanceRankExpr(b, rel)
	// The tier arrives as a string in the cursor payload; the CASE
	// yields an integer, so both comparisons cast explicitly (the
	// generic predicate gets its typing from columnCast — dropped here).
	ltIdx := b.placeholder(cursor.Value)
	c2 := relevanceRankExpr(b, rel)
	eqIdx := b.placeholder(cursor.Value)
	idIdx := b.placeholder(cursor.RowID)
	kindIdx := b.placeholder(cursor.RowKind)
	rowKeyGT := fmt.Sprintf(
		`(row_id > $%d OR (row_id = $%d AND row_kind > $%d))`,
		idIdx, idIdx, kindIdx,
	)
	c3 := relevanceRankExpr(b, rel)
	if cursor.Null {
		// Unreachable for relevance (tiers are never NULL) — kept for
		// shape parity with the generic cursor predicate.
		return fmt.Sprintf("((%s IS NULL AND %s) OR %s IS NOT NULL)", c1, rowKeyGT, c1)
	}
	if dir == DirDesc {
		return fmt.Sprintf("(%s < ($%d)::bigint OR (%s = ($%d)::bigint AND %s))", c1, ltIdx, c2, eqIdx, rowKeyGT)
	}
	return fmt.Sprintf(
		"(%s > ($%d)::bigint OR (%s = ($%d)::bigint AND %s) OR %s IS NULL)",
		c1, ltIdx, c2, eqIdx, rowKeyGT, c3,
	)
}

// columnCast returns the explicit SQL cast for a sort/cursor value of
// the given canonical field, so cursor comparisons are well-typed
// (integer fields compare against ::bigint, timestamp fields against
// ::timestamptz, everything else ::text).
func columnCast(field string) string {
	switch field {
	case "port", "asn", "http.status", "coverage":
		return "::bigint"
	case "relevance":
		// R114: the cursor payload carries the tier rank (an integer).
		return "::bigint"
	case "first_seen", "last_seen", "tls.cert_expiry":
		return "::timestamptz"
	}
	return "::text"
}

// ---------------------------------------------------------------------------
// Field-type lookup (mirrors the validator registry's list/bool typing)
// ---------------------------------------------------------------------------

// isListField reports whether the canonical path is one of the
// text[] columns of search_index.
func isListField(canonical string) bool {
	return canonical == "technologies" || canonical == "sources"
}

// likeEscape backslash-escapes the SQL LIKE/ILIKE special characters
// in s (%, _, \) so the user's CONTAINS value is treated literally
// inside the surrounding %…% pattern.
func likeEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '%', '_':
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Explain
// ---------------------------------------------------------------------------

// Explain renders a human-readable description of the Plan (AST shape,
// branch classification, mode, sort, cursor, limit, timeout, SQL).
// Used by `gseer search --explain`.
func (p *Plan) Explain() string {
	var b strings.Builder
	b.WriteString("GQL Plan\n")
	b.WriteString("--------\n")
	b.WriteString("mode:     " + p.Mode.String() + "\n")
	b.WriteString("branch:   " + p.Branch.String() + "\n")
	b.WriteString("limit:    ")
	if p.Limit == DefaultLimit {
		fmt.Fprintf(&b, "%d (server default)\n", p.Limit)
	} else {
		fmt.Fprintf(&b, "%d\n", p.Limit)
	}
	b.WriteString("timeout:  " + p.Timeout.String() + "\n")
	if len(p.Sort) > 0 {
		parts := make([]string, 0, len(p.Sort))
		for _, s := range p.Sort {
			parts = append(parts, s.Field+":"+s.Direction.String())
		}
		b.WriteString("sort:     " + strings.Join(parts, ", ") + "\n")
	}
	if p.CursorDecoded != nil {
		fmt.Fprintf(&b, "cursor:   field=%s row_id=%d value=%q\n",
			p.CursorDecoded.SortField, p.CursorDecoded.RowID, p.CursorDecoded.Value)
	}
	if len(p.ProjectionFields) > 0 && !equalStringSlices(p.ProjectionFields, allSearchColumns) {
		b.WriteString("fields:   " + strings.Join(p.ProjectionFields, ", ") + "\n")
	}
	b.WriteString("\nSQL\n---\n")
	b.WriteString(p.SQL)
	b.WriteString("\n\nargs:\n")
	for i, a := range p.Args {
		fmt.Fprintf(&b, "  $%d = %v\n", i+1, a)
	}
	return b.String()
}

// equalStringSlices is a shallow equality helper for Explain.
func equalStringSlices(a, b2 []string) bool {
	if len(a) != len(b2) {
		return false
	}
	for i := range a {
		if a[i] != b2[i] {
			return false
		}
	}
	return true
}

// SortedFieldNames returns the sortable field set, sorted (used by
// the search command's help text).
func SortedFieldNames() []string {
	out := make([]string, 0, len(sortableFields))
	for k := range sortableFields {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
