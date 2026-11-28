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

package plannersqlite

// planner_test.go — the SQLite-dialect planner's unit tests: the SQL
// emission contract per operator family (mirroring the PG planner's
// unit tests subset-for-subset), the `?` placeholder discipline, and
// the compile-time failures the PG dialect defers to execution.

import (
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/gql/parser"
	"github.com/Lutfifakee-Project/gseer/internal/gql/planner"
	"github.com/Lutfifakee-Project/gseer/internal/gql/validator"
)

// compile parses, validates and compiles q, returning the plan.
func compile(t *testing.T, q string, opts planner.Options) *Plan {
	t.Helper()
	n, err := parser.Parse(q)
	if err != nil {
		t.Fatalf("Parse(%q): %v", q, err)
	}
	if _, err := validator.Validate(n); err != nil {
		t.Fatalf("Validate(%q): %v", q, err)
	}
	p, err := Compile(n, opts)
	if err != nil {
		t.Fatalf("Compile(%q): %v", q, err)
	}
	return p
}

// TestCompileBasics — the service-mode SELECT shape, projection order,
// default sort and the LIMIT placeholder count.
func TestCompileBasics(t *testing.T) {
	p := compile(t, `port == 443`, planner.Options{})
	if !strings.Contains(p.SQL, "SELECT") || !strings.Contains(p.SQL, "FROM search_index") {
		t.Fatalf("unexpected SQL shape:\n%s", p.SQL)
	}
	if !strings.Contains(p.SQL, `"port" = ?`) {
		t.Errorf("expected \"port\" = ?, got:\n%s", p.SQL)
	}
	if len(p.Args) != 2 || p.Args[0].(int64) != 443 || p.Args[1].(int) != planner.DefaultLimit {
		t.Errorf("args = %v, want [443 %d]", p.Args, planner.DefaultLimit)
	}
	if !strings.Contains(p.SQL, `"last_seen" DESC NULLS FIRST`) {
		t.Errorf("default sort missing:\n%s", p.SQL)
	}
	if !strings.HasSuffix(strings.TrimSpace(p.SQL), "LIMIT ?") {
		t.Errorf("LIMIT ? missing:\n%s", p.SQL)
	}
	// Placeholder count must equal arg count: every ? in the SQL maps
	// to one arg (no stray ? inside string literals in the planner).
	if got := strings.Count(p.SQL, "?"); got != len(p.Args) {
		t.Errorf("? count = %d, args = %d", got, len(p.Args))
	}
}

// TestCompileOperators — one case per operator family.
func TestCompileOperators(t *testing.T) {
	cases := []struct {
		q    string
		want string
	}{
		{`country = "US" && port < 1024`, `(search_index."geo_country" = ? AND search_index."port" < ?)`},
		{`country = "US" || port > 80`, `(search_index."geo_country" = ? OR search_index."port" > ?)`},
		{`not (country = "US")`, `(NOT (search_index."geo_country" = ?))`},
		{`protocol IN ("http", "https")`, `search_index."protocol" IN (?, ?)`},
		{`asn IN (13335, 15169)`, `search_index."asn" IN (?, ?)`},
		{`http.title contains "portal"`, `search_index."http_title" LIKE ? ESCAPE '\'`},
		{`http.title *= "Port?l"`, `search_index."http_title" LIKE ? ESCAPE '\'`},
		{`ip IN_CIDR "198.51.100.0/24"`, `gseer_ip_in_cidr(search_index."ip", ?)`},
		{`domain IN_DOMAIN "example.com"`, `(search_index."domain" = ? OR search_index."domain" LIKE ? ESCAPE '\')`},
		{`technologies contains "nginx"`, `json_each`},
		{`http.title = ""`, `search_index."http_title" IS NULL OR search_index."http_title" = ''`},
		{`http.title != ""`, `search_index."http_title" IS NOT NULL AND search_index."http_title" <> ''`},
		{`is_domain = "true"`, `(search_index."domain" IS NOT NULL AND search_index."domain" <> '')`},
		{`is_ipv6 = "true"`, `instr(search_index."ip", ':') > 0`},
		{`cert.is_expired = "true"`, `gseer_ts(search_index."cert_expiry") < gseer_now_micro()`},
		{`host = "203.0.113.10"`, `(search_index."hostname" = ? OR search_index."ip" = ?)`},
		{`ANY(host){ http.status == 200 }`, `EXISTS (SELECT 1 FROM search_index host_row`},
	}
	for _, tc := range cases {
		p := compile(t, tc.q, planner.Options{})
		if !strings.Contains(p.SQL, tc.want) {
			t.Errorf("%s:\n  want fragment %q in:\n%s", tc.q, tc.want, p.SQL)
		}
	}
}

// TestCompileWildcardEscapes — matchPattern translation identical to PG.
func TestCompileWildcardEscapes(t *testing.T) {
	p := compile(t, `hostname *= "100%_reliabl*"`, planner.Options{})
	got, ok := p.Args[0].(string)
	if !ok {
		t.Fatalf("pattern arg type = %T", p.Args[0])
	}
	if got != `100\%\_reliabl%` {
		t.Errorf("pattern arg = %q", got)
	}
}

// TestCompileFreeText — quoted bare keywords expand to the OR-per-term
// chain over the fixed text fields.
func TestCompileFreeText(t *testing.T) {
	p := compile(t, `"wordpress"`, planner.Options{})
	if !strings.Contains(p.SQL, `"hostname" LIKE ?`) || !strings.Contains(p.SQL, `"product" LIKE ?`) {
		t.Errorf("free-text chain missing text fields:\n%s", p.SQL)
	}
	if !strings.Contains(p.SQL, " OR ") {
		t.Errorf("free-text must OR across fields:\n%s", p.SQL)
	}
}

// TestCompileAssetMode — ROW_NUMBER window replaces PG's DISTINCT ON.
func TestCompileAssetMode(t *testing.T) {
	p := compile(t, `port == 443`, planner.Options{Mode: planner.ModeAsset})
	if !strings.Contains(p.SQL, "ROW_NUMBER() OVER (PARTITION BY \"asset_id\"") {
		t.Errorf("asset-mode window missing:\n%s", p.SQL)
	}
	if !strings.Contains(p.SQL, "WHERE gseer_rn = 1") {
		t.Errorf("rank filter missing:\n%s", p.SQL)
	}
}

// TestCompileCursorPredicate — keyset advancement (non-null + null).
func TestCompileCursorPredicate(t *testing.T) {
	p := compile(t, `port == 443`, planner.Options{
		Sort: []planner.SortSpec{{Field: "last_seen", Direction: planner.DirAsc}},
		Cursor: mustEncode(t, planner.CursorPayload{
			SortField: "last_seen", RowID: 7, RowKind: "service",
			Value: "2026-01-02T00:00:00.000000Z",
		}),
	})
	if !strings.Contains(p.SQL, `"last_seen" > ?`) || !strings.Contains(p.SQL, `"last_seen" = ?`) {
		t.Errorf("ASC advancement missing:\n%s", p.SQL)
	}
	if !strings.Contains(p.SQL, `"last_seen" IS NULL`) {
		t.Errorf("ASC NULL-tail arm missing:\n%s", p.SQL)
	}

	p = compile(t, `port == 443`, planner.Options{
		Sort: []planner.SortSpec{{Field: "asn", Direction: planner.DirAsc}},
		Cursor: mustEncode(t, planner.CursorPayload{
			SortField: "asn", RowID: 3, RowKind: "asset-only", Value: "13335", Null: false,
		}),
	})
	// Args order (SQL appearance): port value, cursor value (lt),
	// cursor value (eq), row_id, row_id, row_kind, then LIMIT.
	if len(p.Args) != 7 {
		t.Fatalf("args = %v, want 7", p.Args)
	}
	if p.Args[1].(int64) != 13335 || p.Args[2].(int64) != 13335 {
		t.Errorf("cursor value args = %v/%v, want 13335/13335", p.Args[1], p.Args[2])
	}
	if p.Args[6].(int) != planner.DefaultLimit {
		t.Errorf("limit arg = %v", p.Args[6])
	}
}

// TestCompileErrors — limit/sort-field/cursor/IN_CIDR failures carry the
// PG planner's codes.
func TestCompileErrors(t *testing.T) {
	n, _ := parser.Parse(`port == 443`)
	validator.Validate(n)

	if _, err := Compile(n, planner.Options{Limit: planner.MaxLimit + 1}); err == nil ||
		!strings.Contains(err.Error(), "GQL_E_PLAN_LIMIT") {
		t.Errorf("limit cap: got %v", err)
	}
	if _, err := Compile(n, planner.Options{Sort: []planner.SortSpec{{Field: "technologies", Direction: planner.DirAsc}}}); err == nil ||
		!strings.Contains(err.Error(), "GQL_E_PLAN_SORT_FIELD") {
		t.Errorf("sort field: got %v", err)
	}
	if _, err := Compile(n, planner.Options{Cursor: "@@bad@@"}); err == nil ||
		!strings.Contains(err.Error(), "GQL_E_PLAN_CURSOR") {
		t.Errorf("cursor: got %v", err)
	}

	n2, _ := parser.Parse(`ip IN_CIDR "not-a-cidr"`)
	validator.Validate(n2)
	_, err := Compile(n2, planner.Options{})
	if err == nil {
		t.Fatal("invalid CIDR must fail at compile time")
	}
	var pe *planner.Error
	if !asPlannerError(err, &pe) {
		t.Fatalf("error type = %T, want *planner.Error", err)
	}
	if pe.Code != planner.CodePlanCursor {
		t.Errorf("code = %s, want %s", pe.Code, planner.CodePlanCursor)
	}
}

// TestCompileWhere — the facet entry point returns the WHERE + args only.
func TestCompileWhere(t *testing.T) {
	n, _ := parser.Parse(`port == 443 && country = "US"`)
	validator.Validate(n)
	where, args, branch, err := CompileWhere(n)
	if err != nil {
		t.Fatalf("CompileWhere: %v", err)
	}
	if !strings.Contains(where, `"port" = ?`) || !strings.Contains(where, `"geo_country" = ?`) {
		t.Errorf("where = %s", where)
	}
	if len(args) != 2 {
		t.Errorf("args = %v, want 2 values", args)
	}
	if !branch.Witness {
		t.Errorf("branch = %+v, want witness", branch)
	}
}

// TestFreeTextFieldListsMatch — the SQLite planner's free-text list is
// pinned to the PG planner's list (they must never drift).
func TestFreeTextFieldListsMatch(t *testing.T) {
	pg := pgFreeTextList(t)
	if len(pg) != len(freeTextFieldPaths) {
		t.Fatalf("length mismatch: pg=%d sqlite=%d", len(pg), len(freeTextFieldPaths))
	}
	for i := range pg {
		if pg[i] != freeTextFieldPaths[i] {
			t.Errorf("item %d: pg=%q sqlite=%q", i, pg[i], freeTextFieldPaths[i])
		}
	}
}

// TestCompileR37Fields — the R37 search-field expansion: the dynamic
// per-name header field lowers to json_extract over http_headers; the
// static prefix field maps to ip_prefix; banner/cert_issuer_org map to
// their view columns.
// TestCompileR38Fields — the R38 additions: parentheses group the
// boolean expression; tls.cert_not_before lowers to its view column;
// the `service` alias resolves to the name column.
func TestCompileR38Fields(t *testing.T) {
	p := compile(t, `port >= 1 AND (asn == 13335 OR asn == 8553)`, planner.Options{})
	if !strings.Contains(p.SQL, "(") || !strings.Contains(p.SQL, `"asn"`) {
		t.Errorf("parenthesised group missing:\n%s", p.SQL)
	}
	p = compile(t, `tls.cert_not_before >= "2026-01-01T00:00:00Z"`, planner.Options{})
	if !strings.Contains(p.SQL, `"cert_not_before"`) {
		t.Errorf("cert_not_before column missing:\n%s", p.SQL)
	}
	p = compile(t, `service == "https"`, planner.Options{})
	if !strings.Contains(p.SQL, `"name"`) {
		t.Errorf("service → name alias missing:\n%s", p.SQL)
	}
}

func TestCompileR37Fields(t *testing.T) {
	p := compile(t, `http.header.x-powered-by == "Next.js"`, planner.Options{})
	if !strings.Contains(p.SQL, `json_extract(search_index."http_headers", '$."x-powered-by"')`) {
		t.Errorf("dynamic header expr missing:\n%s", p.SQL)
	}
	p = compile(t, `prefix == "198.51.100.0/24"`, planner.Options{})
	if !strings.Contains(p.SQL, `"ip_prefix" = ?`) {
		t.Errorf("prefix → ip_prefix missing:\n%s", p.SQL)
	}
	p = compile(t, `banner *= "*OpenSSH*"`, planner.Options{})
	if !strings.Contains(p.SQL, `"banner"`) {
		t.Errorf("banner column missing:\n%s", p.SQL)
	}
	p = compile(t, `tls.cert_issuer_org CONTAINS "SSL"`, planner.Options{})
	if !strings.Contains(p.SQL, `"cert_issuer_org"`) {
		t.Errorf("cert_issuer_org column missing:\n%s", p.SQL)
	}
}

// TestCompileR39CTFields — the R39 CT search surface (migration 0009):
// ct.* lowers to its ct_* view columns; a CT record is a name in a
// cryptographically logged certificate, kept distinct from the live
// tls.* observation fields.
func TestCompileR39CTFields(t *testing.T) {
	p := compile(t, `ct.not_after >= "2026-01-01T00:00:00Z"`, planner.Options{})
	if !strings.Contains(p.SQL, `"ct_not_after"`) {
		t.Errorf("ct_not_after column missing:\n%s", p.SQL)
	}
	p = compile(t, `ct.subject *= "*.example.com"`, planner.Options{})
	if !strings.Contains(p.SQL, `"ct_subject_cn"`) {
		t.Errorf("ct_subject_cn column missing:\n%s", p.SQL)
	}
	p = compile(t, `ct.issuer == "Let's Encrypt"`, planner.Options{})
	if !strings.Contains(p.SQL, `"ct_issuer"`) {
		t.Errorf("ct_issuer column missing:\n%s", p.SQL)
	}
	p = compile(t, `ct.leaf_sha256 == "abc123"`, planner.Options{})
	if !strings.Contains(p.SQL, `"ct_leaf_sha256"`) {
		t.Errorf("ct_leaf_sha256 column missing:\n%s", p.SQL)
	}
	p = compile(t, `ct.log CONTAINS "nimbus"`, planner.Options{})
	if !strings.Contains(p.SQL, `"ct_log"`) {
		t.Errorf("ct_log column missing:\n%s", p.SQL)
	}
}

// TestCompileR39DNSFields — the R39 dynamic dns.<key> fields (migration
// 0010): dns.type / dns.query / dns.value lower to json_extract over
// the latest_dns projection (dns_record), mirroring http.header.<name>.
func TestCompileR39DNSFields(t *testing.T) {
	p := compile(t, `dns.type == "AAAA"`, planner.Options{})
	if !strings.Contains(p.SQL, `json_extract(search_index."dns_record", '$."type"')`) {
		t.Errorf("dns.type lowering missing:\n%s", p.SQL)
	}
	p = compile(t, `dns.query == "venicebiennale.ro"`, planner.Options{})
	if !strings.Contains(p.SQL, `'$."query"'`) {
		t.Errorf("dns.query lowering missing:\n%s", p.SQL)
	}
	p = compile(t, `dns.value CONTAINS "spf"`, planner.Options{})
	if !strings.Contains(p.SQL, `'$."value"'`) {
		t.Errorf("dns.value lowering missing:\n%s", p.SQL)
	}
}
