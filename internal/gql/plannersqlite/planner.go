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

// Package plannersqlite lowers a validated GQL AST to parameterized SQL
// for the SQLite personal-mode engine (database/sql + modernc driver).
//
// It is a DIALECT SIBLING of internal/gql/planner (the PostgreSQL
// planner), not a replacement: the PG planner is untouched and remains
// the canonical dialect for the self-hosted profile.  This package
// mirrors the PG planner's semantics subset-for-subset so personal-mode
// Search behaves like PostgreSQL for every feature the personal engine
// supports: comparisons, IN, CONTAINS, *= wildcards, IN_CIDR (via the
// registered gseer_ip_in_cidr scalar function), IN_DOMAIN, empty-value
// semantics, free-text, derived booleans, the host_or_ip compat field,
// after/before rewrites (the validator rewrites them before planning),
// ANY(service)/ANY(host), keyset cursor pagination with identical
// NULL-placement rules, and the service/asset modes.
//
// Documented dialect differences (docs/PERSONAL.md):
//   - placeholders are `?` (database/sql style), not $N;
//   - ILIKE is spelled LIKE — SQLite's LIKE is case-insensitive for
//     ASCII, the parity surface GSEER guarantees; non-ASCII case
//     folding is a limitation;
//   - list membership lowers to json_each over the JSON array column
//     instead of PG's @> ARRAY[];
//   - first_seen/last_seen are stored as fixed-width UTC microsecond
//     ISO strings (SQ-02), so lexicographic order equals chronological
//     order; cert_expiry — whose stored format comes from evidence —
//     compares through the gseer_ts normalizer function on both sides.
package plannersqlite

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/gql/ast"
	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
)

// Compile lowers a validated AST to a parameterized SQLite Plan.
// Pre-condition: root has been through validator.Validate — the same
// contract as the PG planner's Compile.
func Compile(root ast.Node, opts planner.Options) (*Plan, error) {
	if root == nil {
		return nil, &planner.Error{
			Code:   planner.CodePlanEmpty,
			Detail: "no query to compile",
			Why:    "Compile was called with a nil AST root",
			Next:   "supply a parsed-and-validated GQL expression",
		}
	}
	limit, timeout, sorts, err := compileOptions(opts)
	if err != nil {
		return nil, err
	}
	_ = timeout // kept on Plan for the caller's context deadline
	projection, err := resolveProjection(opts.Fields)
	if err != nil {
		return nil, err
	}
	cursorPayload, err := planner.DecodeCursor(opts.Cursor)
	if err != nil {
		return nil, err
	}
	if cursorPayload != nil && cursorPayload.SortField != sorts[0].Field {
		return nil, &planner.Error{
			Code:   planner.CodePlanCursor,
			Detail: fmt.Sprintf("cursor was for sort field %q; current sort starts with %q", cursorPayload.SortField, sorts[0].Field),
			Why:    "a cursor is tied to the sort order of the page that produced it",
			Next:   "drop --cursor to start a fresh page, or restore the matching --sort",
		}
	}

	b := &builder{}
	branch := planner.Branch{}
	whereSQL := b.compileNode(root, "search_index", &branch)
	if b.err != nil {
		return nil, b.err
	}
	if !branch.Witness && !branch.AnyUnion && !branch.AnyService {
		// The root was a leaf — implicit witness (same rule as PG).
		branch.Witness = true
	}

	var curPred string
	whereSQLNoCursor := whereSQL
	if cursorPayload != nil {
		curPred = b.renderCursorPredicate(sorts[0], cursorPayload, opts.Relevance)
		whereSQL = "(" + whereSQL + " AND " + curPred + ")"
	}

	// BINDING ORDER CONTRACT (SQLite binds `?` by ordinal over the whole
	// statement): WHERE args first (b.args, cursor predicate included —
	// its text was appended last inside WHERE), then the relevance rank
	// args from the ORDER BY clause, then LIMIT.
	sortClause, rankArgs := renderSort(sorts, opts.Relevance)
	args := append([]any{}, b.args...)
	args = append(args, rankArgs...)
	args = append(args, limit)

	if opts.Mode == planner.ModeAsset {
		branch.AssetAll = true
	}
	sqlStr := composeSelect(opts.Mode, projection, sorts, whereSQL, whereSQLNoCursor, curPred, sortClause)

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

// CompileWhere compiles a validated AST into ONLY the WHERE clause with
// `?` placeholders and its args — the facet engine's entry point.
func CompileWhere(root ast.Node) (where string, args []any, branch planner.Branch, err error) {
	if root == nil {
		return "", nil, planner.Branch{}, &planner.Error{
			Code:   planner.CodePlanEmpty,
			Detail: "no query to compile",
			Why:    "CompileWhere was called with a nil AST root",
			Next:   "supply a parsed-and-validated GQL expression",
		}
	}
	b := &builder{}
	branch = planner.Branch{}
	where = b.compileNode(root, "search_index", &branch)
	if b.err != nil {
		return "", nil, planner.Branch{}, b.err
	}
	if !branch.Witness && !branch.AnyUnion && !branch.AnyService {
		branch.Witness = true
	}
	return where, b.args, branch, nil
}

// Plan is the compiled SQLite query (the fields the execution layer
// needs; the timeout is enforced by the caller via a context deadline —
// SQLite has no statement_timeout).
type Plan struct {
	SQL              string
	Args             []any
	Branch           planner.Branch
	Mode             planner.Mode
	Sort             []planner.SortSpec
	Limit            int
	Timeout          time.Duration
	CursorDecoded    *planner.CursorPayload
	ProjectionFields []string
	// Relevance (R114) — carried so the result layer can compute the
	// same tier per row when encoding the pagination cursor.
	Relevance *planner.RelevanceAnchor
}

// compileOptions mirrors the PG planner's option validation and
// defaults (limit cap, timeout bounds, sort registry, default sort
// last_seen DESC).
func compileOptions(opts planner.Options) (int, time.Duration, []planner.SortSpec, error) {
	if opts.Limit < 0 || opts.Limit > planner.MaxLimit {
		return 0, 0, nil, &planner.Error{
			Code:   planner.CodePlanLimit,
			Detail: fmt.Sprintf("limit %d is out of range (0–%d)", opts.Limit, planner.MaxLimit),
			Why:    "0 means the server default; the hard cap protects the API",
			Next:   fmt.Sprintf("try: --limit %d", planner.DefaultLimit),
		}
	}
	limit := opts.Limit
	if limit == 0 {
		limit = planner.DefaultLimit
	}
	if opts.Timeout > 0 && (opts.Timeout < planner.MinTimeout || opts.Timeout > planner.MaxTimeout) {
		return 0, 0, nil, &planner.Error{
			Code:   planner.CodePlanTimeout,
			Detail: fmt.Sprintf("timeout %s is out of range (%s–%s)", opts.Timeout, planner.MinTimeout, planner.MaxTimeout),
			Why:    "the hard cap is 30s; sub-100ms timeouts are not useful",
			Next:   "try: --timeout 5s",
		}
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	sorts := opts.Sort
	if len(sorts) == 0 {
		// R114: with a relevance anchor and no user sort, relevance
		// (exact > prefix > substring) leads.  The ONLY secondary keys
		// are the composite row key — the pagination cursor compares
		// (tier, row_id, row_kind), so any other tiebreaker would make
		// pages skip or repeat rows (the same contract as the coverage
		// rank).  Recency tie-breaking within a tier needs a two-key
		// cursor and is deliberately out of scope.
		if opts.Relevance != nil {
			sorts = []planner.SortSpec{{Field: "relevance", Direction: planner.DirAsc}}
		} else {
			sorts = []planner.SortSpec{{Field: "last_seen", Direction: planner.DirDesc}}
		}
	}
	for _, s := range sorts {
		if !sortableFields[s.Field] {
			return 0, 0, nil, &planner.Error{
				Code:   planner.CodePlanSortField,
				Detail: fmt.Sprintf("field %q is not sortable", s.Field),
				Why:    "list and bool fields have no meaningful ordering; row_id and the witness fields are sortable",
				Next:   "try: --sort last_seen:desc",
			}
		}
		if s.Field == "relevance" && opts.Relevance == nil {
			return 0, 0, nil, &planner.Error{
				Code:   planner.CodePlanSortField,
				Detail: `sort "relevance" requires a text-match query`,
				Why:    "the relevance rank is derived from a single substring-family predicate (CONTAINS, *=, IN_DOMAIN); this query has none",
				Next:   `try: product CONTAINS "nginx" --sort relevance:asc`,
			}
		}
	}
	return limit, timeout, sorts, nil
}

// ---------------------------------------------------------------------------
// Field → column mapping (identical column names to the PG search_index
// view — the SQLite view in the personal migration mirrors the same
// contract, so projection and sorts are 1:1 with the PG planner).
// ---------------------------------------------------------------------------

var searchColumns = map[string]string{
	"ip":                  "ip",
	"asset_value":         "asset_value",
	"asset_kind":          "asset_kind",
	"domain":              "domain",
	"hostname":            "hostname",
	"asn":                 "asn",
	"asn_org":             "asn_org",
	"geo_country":         "geo_country",
	"geo_region":          "geo_region",
	"geo_city":            "geo_city",
	"port":                "port",
	"transport":           "transport",
	"protocol":            "protocol",
	"name":                "name",
	"product":             "product",
	"version":             "version",
	"http.status":         "http_status",
	"http.title":          "http_title",
	"http.server":         "http_server",
	"tls.version":         "tls_version",
	"tls.cert_subject_cn": "cert_subject_cn",
	"tls.cert_issuer_cn":  "cert_issuer_cn",
	"tls.cert_expiry":     "cert_expiry",
	"tls.cert_serial":     "cert_serial",
	"tls.cert_sans_dns":   "cert_sans_dns",
	"tls.cert_not_before": "cert_not_before",
	"technologies":        "technologies",
	"sources":             "sources",
	"first_seen":          "first_seen",
	"last_seen":           "last_seen",
	"stale":               "stale",
	// R36 evidence quality + R37 field expansion (0006/0007 project
	// them into the personal-store view).
	"coverage":            "coverage_class",
	"last_observed":       "last_observed",
	"prefix":              "ip_prefix",
	"banner":              "banner",
	"tls.cert_issuer_org": "cert_issuer_org",
	"http.headers":        "http_headers",
	"evidence":            "evidence_kinds",
	// R39 P2 — the CT search surface (migration 0009 projects $.ctlog
	// evidence into the personal-store view).
	"ct.log":            "ct_log",
	"ct.entry_type":     "ct_entry_type",
	"ct.subject":        "ct_subject_cn",
	"ct.issuer":         "ct_issuer",
	"ct.not_before":     "ct_not_before",
	"ct.not_after":      "ct_not_after",
	"ct.leaf_sha256":    "ct_leaf_sha256",
	"ct.cert_timestamp": "ct_cert_timestamp",
}

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

// allSearchColumns is the canonical projection list, in view order —
// identical to the PG planner's list (same view contract).
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

func columnName(canonical string) string {
	if c, ok := searchColumns[canonical]; ok {
		return c
	}
	return ""
}

func resolveProjectionColumn(name string) string {
	if c := columnName(name); c != "" {
		return c
	}
	for _, col := range searchColumns {
		if col == name {
			return col
		}
	}
	return ""
}

func resolveProjection(fields []string) ([]string, error) {
	if len(fields) == 0 {
		return allSearchColumns, nil
	}
	resolved := make([]string, 0, len(fields))
	for _, f := range fields {
		col := resolveProjectionColumn(f)
		if col == "" {
			switch f {
			case "row_id", "row_kind", "asset_id":
				col = f
			default:
				return nil, &planner.Error{
					Code:   planner.CodePlanProjection,
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

// ---------------------------------------------------------------------------
// composeSelect — the mode-aware SELECT.  ModeAsset wraps the body in a
// ROW_NUMBER() CTE (SQLite has no DISTINCT ON; ROW_NUMBER OVER
// (PARTITION BY asset_id ORDER BY last_seen DESC, row_id ASC) keeps one
// row per asset with the same representative-row rule as PG).
// ---------------------------------------------------------------------------

func composeSelect(mode planner.Mode, projection []string, sorts []planner.SortSpec, whereSQL, whereSQLNoCursor, curPred, sortClause string) string {
	projCols := strings.Join(quoteIdentList(projection), ", ")

	var sql strings.Builder
	if mode == planner.ModeAsset {
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
		sql.WriteString("  SELECT " + innerCols + " FROM (\n")
		sql.WriteString("    SELECT " + innerCols + ", ROW_NUMBER() OVER (PARTITION BY \"asset_id\" ORDER BY \"last_seen\" DESC, \"row_id\" ASC) AS gseer_rn\n")
		sql.WriteString("    FROM search_index\n")
		sql.WriteString("    WHERE " + whereSQLNoCursor + "\n")
		sql.WriteString("  ) WHERE gseer_rn = 1\n")
		sql.WriteString(")\n")
		sql.WriteString("SELECT " + projCols + " FROM page\n")
		if curPred != "" {
			sql.WriteString("WHERE " + curPred + "\n")
		}
		sql.WriteString("ORDER BY " + sortClause + "\n")
		sql.WriteString("LIMIT ?\n")
	} else {
		sql.WriteString("SELECT " + projCols + " FROM search_index\n")
		sql.WriteString("WHERE " + whereSQL + "\n")
		sql.WriteString("ORDER BY " + sortClause + "\n")
		sql.WriteString("LIMIT ?\n")
	}
	return sql.String()
}

func quoteIdentList(cols []string) []string {
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = `"` + strings.ReplaceAll(c, `"`, `""`) + `"`
	}
	return out
}

func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// builder — recursive WHERE-clause compiler (dialect: SQLite)
// ---------------------------------------------------------------------------

type builder struct {
	args []any
	err  error // first compile error (e.g. invalid CIDR prefix)
}

func (b *builder) placeholder(v any) string {
	b.args = append(b.args, v)
	return "?"
}

func (b *builder) compileNode(n ast.Node, alias string, branch *planner.Branch) string {
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
			col = t.Field
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

func (b *builder) compileComparison(c *ast.Comparison, alias string, branch *planner.Branch) string {
	if sql, ok := b.compileDerived(c, alias); ok {
		return sql
	}
	if sql, ok := b.compileHostOrIP(c, alias); ok {
		return sql
	}
	// R37 dynamic per-name header fields (http.header.<name> and the
	// http.headers.<name> alias form) lower to json_extract over the
	// captured headers object; the name is validator-charset checked
	// ([a-z0-9_-]+), so the quoted JSON path is safe.
	if name, ok := dynamicHeaderKey(c.Field); ok {
		branch.Witness = true
		return b.compileColumnOps(fmt.Sprintf(`json_extract(%s."http_headers", '$."%s"')`, alias, name), c)
	}
	// R39 P4 dynamic dns.<key> fields lower to json_extract over the
	// latest_dns projection (dns_record); the key is validator-charset
	// checked, so the quoted JSON path is safe.
	if name, ok := dynamicDNSKey(c.Field); ok {
		branch.Witness = true
		return b.compileColumnOps(fmt.Sprintf(`json_extract(%s."dns_record", '$."%s"')`, alias, name), c)
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
		// Empty-value semantics identical to the PG planner.
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
		return b.compileMatch(qcol, c.Value)
	}
	return "TRUE"
}

// compileDerived lowers the compatibility boolean fields — same
// semantics as PG, SQLite spellings (instr instead of position,
// gseer_ts/gseer_now_micro for the certificate expiry wall clock).
func (b *builder) compileDerived(c *ast.Comparison, alias string) (string, bool) {
	want, ok := boolValue(c.Value)
	if !ok {
		return "", false
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
		ip := colOf("ip")
		if want {
			return fmt.Sprintf("(%s IS NOT NULL AND instr(%s, ':') > 0)", ip, ip), true
		}
		return fmt.Sprintf("(%s IS NOT NULL AND instr(%s, ':') = 0)", ip, ip), true
	case "cert.is_expired":
		e := colOf("tls.cert_expiry")
		if want {
			return fmt.Sprintf("(%s IS NOT NULL AND gseer_ts(%s) < gseer_now_micro())", e, e), true
		}
		return fmt.Sprintf("(%s IS NOT NULL AND gseer_ts(%s) >= gseer_now_micro())", e, e), true
	}
	return "", false
}

// compileHostOrIP lowers the compatibility field host_or_ip — the ip
// column stores the canonical address WITHOUT any /32 suffix (storage
// contract), so plain text equality matches.
func (b *builder) compileHostOrIP(c *ast.Comparison, alias string) (string, bool) {
	if c.Field != "host_or_ip" {
		return "", false
	}
	h := alias + ".\"hostname\""
	i := alias + ".\"ip\""
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

// simpleCompare binds text/int values with ? placeholders.  Time fields
// (written by the storage layer as fixed-width UTC micro strings,
// SQ-02) compare lexicographically = chronologically, so they take the
// plain text path too.
func (b *builder) simpleCompare(qcol, op string, v ast.Value) string {
	switch val := v.(type) {
	case *ast.StrValue:
		return fmt.Sprintf("%s %s %s", qcol, op, b.placeholder(val.S))
	case *ast.IntValue:
		return fmt.Sprintf("%s %s %s", qcol, op, b.placeholder(val.N))
	case *ast.ListValue:
		var parts []string
		for _, item := range val.Items {
			parts = append(parts, b.simpleCompare(qcol, op, item))
		}
		if len(parts) == 0 {
			return "FALSE"
		}
		return "(" + strings.Join(parts, " OR ") + ")"
	}
	return "FALSE"
}

// compileIn lowers `field IN (a, b, …)` to `field IN (?, ?, …)`.
func (b *builder) compileIn(qcol string, v ast.Value) string {
	list, ok := v.(*ast.ListValue)
	if !ok {
		return b.simpleCompare(qcol, "=", v)
	}
	if len(list.Items) == 0 {
		return "FALSE"
	}
	ph := make([]string, 0, len(list.Items))
	switch list.Items[0].(type) {
	case *ast.IntValue:
		for _, it := range list.Items {
			if iv, ok := it.(*ast.IntValue); ok {
				ph = append(ph, b.placeholder(iv.N))
			}
		}
	default:
		for _, it := range list.Items {
			if sv, ok := it.(*ast.StrValue); ok {
				ph = append(ph, b.placeholder(sv.S))
			}
		}
	}
	if len(ph) == 0 {
		return "FALSE"
	}
	return fmt.Sprintf("%s IN (%s)", qcol, strings.Join(ph, ", "))
}

// compileContains lowers `field CONTAINS value`:
//   - list fields (technologies, sources): json_each membership over
//     the JSON array column (guarded by json_valid for defense);
//   - string fields: case-insensitive substring LIKE '%…%'.
func (b *builder) compileContains(qcol string, v ast.Value, canonicalField string) string {
	if isListField(canonicalField) {
		if sv, ok := v.(*ast.StrValue); ok {
			return fmt.Sprintf(
				"EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(%s) THEN %s ELSE '[]' END) WHERE json_each.value = %s)",
				qcol, qcol, b.placeholder(sv.S))
		}
		if iv, ok := v.(*ast.IntValue); ok {
			return fmt.Sprintf(
				"EXISTS (SELECT 1 FROM json_each(CASE WHEN json_valid(%s) THEN %s ELSE '[]' END) WHERE json_each.value = %s)",
				qcol, qcol, b.placeholder(strconv.FormatInt(iv.N, 10)))
		}
		return "FALSE"
	}
	if sv, ok := v.(*ast.StrValue); ok {
		return fmt.Sprintf("%s LIKE %s ESCAPE '\\'", qcol, b.placeholder("%"+likeEscape(sv.S)+"%"))
	}
	return "FALSE"
}

// compileInCidr lowers `ip IN_CIDR "10.0.0.0/8"` to the registered
// gseer_ip_in_cidr(ip, prefix) scalar function (netip containment in
// Go; NULL/invalid → no match).  A value that is not a valid prefix is
// a compile-time error — the PG dialect fails at execution with a
// SQLSTATE, and personal mode must fail with the same seriousness, not
// silently return an empty result.
func (b *builder) compileInCidr(qcol string, v ast.Value) string {
	if sv, ok := v.(*ast.StrValue); ok {
		if _, _, err := parsePrefix(sv.S); err != nil {
			if b.err == nil {
				b.err = &planner.Error{
					Code:   planner.CodePlanCursor,
					Detail: fmt.Sprintf("IN_CIDR value %q is not a valid CIDR prefix", sv.S),
					Why:    err.Error(),
					Next:   `try: ip IN_CIDR "198.51.100.0/24"`,
				}
			}
			return "FALSE"
		}
		return fmt.Sprintf("gseer_ip_in_cidr(%s, %s)", qcol, b.placeholder(sv.S))
	}
	return "FALSE"
}

// compileInDomain lowers `domain IN_DOMAIN "example.com"` to
// `domain = ? OR domain LIKE '%.?'` — the OR-form matches the domain
// itself and any subdomain (identical semantics to the PG planner).
func (b *builder) compileInDomain(qcol string, v ast.Value) string {
	if sv, ok := v.(*ast.StrValue); ok {
		eq := b.placeholder(sv.S)
		pat := b.placeholder("%." + likeEscape(sv.S))
		return fmt.Sprintf("(%s = %s OR %s LIKE %s ESCAPE '\\')", qcol, eq, qcol, pat)
	}
	return "FALSE"
}

// compileMatch lowers `field *= "pattern"` to a case-insensitive
// wildcard LIKE: * → %, ? → _, everything else literal (the same
// translation as the PG planner's matchPattern).
func (b *builder) compileMatch(qcol string, v ast.Value) string {
	sv, ok := v.(*ast.StrValue)
	if !ok {
		return "FALSE"
	}
	return fmt.Sprintf("%s LIKE %s ESCAPE '\\'", qcol, b.placeholder(matchPattern(sv.S)))
}

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

// compileQuantified lowers ANY(host){ body } and ANY(service){ body }
// with the same semantics as the PG planner: ANY(service) folds inline;
// ANY(host) becomes a correlated EXISTS over service-granular rows of
// the same asset.
func (b *builder) compileQuantified(q *ast.Quantified, alias string, branch *planner.Branch) string {
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
	return "FALSE"
}

// compileFreeText defensively lowers the free-text node (the validator
// normally expands it; the planner stays self-contained).  Semantics
// match the PG planner: OR across the free-text columns per term, AND
// across terms.
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

// freeTextFieldPaths mirrors validator.FreeTextFields (the same pin the
// PG planner keeps; TestFreeTextFieldListsMatch pins all three lists).
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
	return "="
}

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

func isListField(canonical string) bool {
	return canonical == "technologies" || canonical == "sources" || canonical == "evidence"
}

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
// Sort + cursor (identical NULL-placement rules to the PG planner)
// ---------------------------------------------------------------------------

// renderSort renders the ORDER BY clause.  The relevance field (R114)
// expands to the anchor's tier CASE; its placeholders are returned
// separately and MUST be bound after every WHERE argument (see the
// binding-order contract in Compile).
func renderSort(sorts []planner.SortSpec, rel *planner.RelevanceAnchor) (string, []any) {
	parts := make([]string, 0, len(sorts)+2)
	var args []any
	for _, s := range sorts {
		col := columnName(s.Field)
		if col == "" {
			col = s.Field
		}
		nulls := "NULLS LAST"
		if s.Direction == planner.DirDesc {
			nulls = "NULLS FIRST"
		}
		expr := fmt.Sprintf("\"%s\"", col)
		if col == "coverage_class" {
			expr = coverageRankExpr(expr)
		}
		if s.Field == "relevance" && rel != nil {
			e, a := relevanceRankExpr(rel)
			expr = e
			args = append(args, a...)
		}
		parts = append(parts, fmt.Sprintf("%s %s %s", expr, s.Direction.String(), nulls))
	}
	parts = append(parts, `"row_id" ASC NULLS LAST`, `"row_kind" ASC`)
	return strings.Join(parts, ", "), args
}

// relevanceRankExpr renders the R114 tier CASE for the anchor's
// predicate family.  Tier 0 = exact (case-insensitive), tier 1 =
// prefix (CONTAINS only), tier 2 = the rest of the matched set.  The
// numbers must stay in lockstep with planner.RelevanceAnchor.Tier —
// the cursor payload carries the tier, and page 2 compares it against
// this same expression.
func relevanceRankExpr(rel *planner.RelevanceAnchor) (string, []any) {
	col := columnName(rel.Field)
	if col == "" {
		col = rel.Field
	}
	qcol := `"` + col + `"`
	switch rel.Kind {
	case planner.RelContains:
		eq := rel.Value
		prefix := likeEscape(rel.Value) + "%"
		return fmt.Sprintf(`CASE WHEN %s = ? COLLATE NOCASE THEN 0
			 WHEN %s LIKE ? ESCAPE '\' THEN 1
			 ELSE 2 END`, qcol, qcol), []any{eq, prefix}
	case planner.RelMatch:
		return fmt.Sprintf(`CASE WHEN %s = ? COLLATE NOCASE THEN 0 ELSE 1 END`, qcol), []any{rel.Core}
	case planner.RelInDomain:
		return fmt.Sprintf(`CASE WHEN %s = ? COLLATE NOCASE THEN 0 ELSE 1 END`, qcol), []any{rel.Value}
	}
	return "0", nil
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
// primary sort column — identical NULL-aware rules to the PG planner
// (ASC → NULLS LAST / DESC → NULLS FIRST / always-ASC tiebreaker over
// the composite (row_id, row_kind) row key).
func (b *builder) renderCursorPredicate(primary planner.SortSpec, cursor *planner.CursorPayload, rel *planner.RelevanceAnchor) string {
	col := columnName(primary.Field)
	if col == "" {
		col = primary.Field
	}
	qcol := `"` + col + `"`
	if primary.Field == "relevance" && rel != nil {
		// R114: the ORDER BY ranked by the tier CASE; the cursor
		// predicate must compare the SAME expression or pages would
		// skip or repeat rows (same rule as the coverage rank).  Unlike
		// the constant coverage CASE, the tier CASE carries placeholders
		// and appears THREE times below — each occurrence binds its own
		// copy, in text order.
		return b.relevanceCursorPredicate(rel, cursor, primary.Direction)
	}
	if col == "coverage_class" {
		// R45: the ORDER BY used the evidence-strength CASE; the cursor
		// predicate must compare the SAME expression or pages would skip
		// or repeat rows.
		qcol = coverageRankExpr(qcol)
	}
	if col == "cert_expiry" {
		// cert_expiry comes from evidence with a caller-chosen format;
		// route both sides through the gseer_ts normalizer so the
		// comparison stays chronological regardless of the stored form.
		qcol = fmt.Sprintf("gseer_ts(%s)", qcol)
	}

	// BINDING ORDER CONTRACT: SQLite numbers every `?` by its position
	// in the final SQL, so placeholders must be created in the exact
	// order their fragments appear.  The value compare binds FIRST (it
	// appears first), then the row-key fragment.
	rowKeyGT := "" // built after the value placeholders
	if cursor.Null {
		rowKeyGT = fmt.Sprintf(
			"(\"row_id\" > %s OR (\"row_id\" = %s AND \"row_kind\" > %s))",
			b.placeholder(cursor.RowID), b.placeholder(cursor.RowID), b.placeholder(cursor.RowKind),
		)
		if primary.Direction == planner.DirDesc {
			return fmt.Sprintf("((%s IS NULL AND %s) OR %s IS NOT NULL)", qcol, rowKeyGT, qcol)
		}
		return fmt.Sprintf("(%s IS NULL AND %s)", qcol, rowKeyGT)
	}

	val := cursorValueArg(primary.Field, cursor.Value)
	// Two occurrences (strict compare + tiebreaker equality), each its
	// own positional parameter.
	ltPh := b.placeholder(val)
	eqPh := b.placeholder(val)
	rowKeyGT = fmt.Sprintf(
		"(\"row_id\" > %s OR (\"row_id\" = %s AND \"row_kind\" > %s))",
		b.placeholder(cursor.RowID), b.placeholder(cursor.RowID), b.placeholder(cursor.RowKind),
	)
	if primary.Direction == planner.DirDesc {
		return fmt.Sprintf(
			"(%s < %s OR (%s = %s AND %s))",
			qcol, ltPh, qcol, eqPh, rowKeyGT,
		)
	}
	return fmt.Sprintf(
		"(%s > %s OR (%s = %s AND %s) OR %s IS NULL)",
		qcol, ltPh, qcol, eqPh, rowKeyGT, qcol,
	)
}

// relevanceCursorPredicate renders the strict-advancement predicate
// for the relevance tier (R114).  Binding order follows SQL text order:
// occurrence 1 of the tier CASE, the strict-compare value, occurrence
// 2, the tiebreaker-equality value, the composite row key, occurrence
// 3 (the ASC NULL-tail check; the tier is never NULL so it only
// completes the shape).
func (b *builder) relevanceCursorPredicate(rel *planner.RelevanceAnchor, cursor *planner.CursorPayload, dir planner.Direction) string {
	// The SQLite rank renderer RETURNS its args (it has no builder), so
	// each occurrence's args are appended here, in text order.
	c1, a1 := relevanceRankExpr(rel)
	b.args = append(b.args, a1...)
	ltPh := b.placeholder(cursorValueArg("relevance", cursor.Value))
	c2, a2 := relevanceRankExpr(rel)
	b.args = append(b.args, a2...)
	eqPh := b.placeholder(cursorValueArg("relevance", cursor.Value))
	rowKeyGT := fmt.Sprintf(
		"(\"row_id\" > %s OR (\"row_id\" = %s AND \"row_kind\" > %s))",
		b.placeholder(cursor.RowID), b.placeholder(cursor.RowID), b.placeholder(cursor.RowKind),
	)
	c3, a3 := relevanceRankExpr(rel)
	b.args = append(b.args, a3...)
	if cursor.Null {
		// Unreachable for relevance (tiers are never NULL) — kept for
		// shape parity with the generic cursor predicate.
		return fmt.Sprintf("((%s IS NULL AND %s) OR %s IS NOT NULL)", c1, rowKeyGT, c1)
	}
	if dir == planner.DirDesc {
		return fmt.Sprintf("(%s < %s OR (%s = %s AND %s))", c1, ltPh, c2, eqPh, rowKeyGT)
	}
	return fmt.Sprintf(
		"(%s > %s OR (%s = %s AND %s) OR %s IS NULL)",
		c1, ltPh, c2, eqPh, rowKeyGT, c3,
	)
}

// cursorValueArg converts the cursor's string-encoded value to the sort
// column's Go type (int64 for integer fields) so the comparison is
// well-typed without SQL casts.
func cursorValueArg(field, value string) any {
	switch field {
	case "port", "asn", "http.status":
		n, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			return n
		}
		return value
	case "coverage":
		// R45: the cursor carries the evidence-strength RANK (an int64),
		// never the class string — the ORDER BY and the cursor predicate
		// compare the CASE expression, so the bound value must be numeric.
		n, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			return n
		}
		return value
	case "relevance":
		// R114: the cursor carries the relevance tier (an int64) — same
		// contract as coverage.
		n, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			return n
		}
		return value
	}
	return value
}
