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

package relations

// dialect_test.go — PG parity contract (tested without a server): the
// PostgreSQL rewrite must number every placeholder in order, cast the
// JSONB dns_record to text, and normalize timestamps identically.
// (A live green-path PG run is sandbox-blocked — no PG binaries, no
// docker, no root for apt — documented in R61-PG-PARITY-EVIDENCE.md.)

import (
	"strings"
	"testing"
	"time"
)

func TestPostgresPlaceholderRewrite(t *testing.T) {
	x := &dbx{dia: DialectPostgres}
	got := x.sql(`SELECT a FROM t WHERE b = ? AND c = ? AND instr(t.dns_record, ?) > 0 LIMIT ?`)
	if strings.Contains(got, "?") {
		t.Fatalf("PG rewrite left a bare ?: %s", got)
	}
	for _, frag := range []string{"b = $1", "c = $2", "$3", "LIMIT $4"} {
		if !strings.Contains(got, frag) {
			t.Fatalf("PG rewrite missing %q in %s", frag, got)
		}
	}
	if !strings.Contains(got, "t.dns_record::text") {
		t.Fatalf("PG rewrite must cast JSONB dns_record to text: %s", got)
	}
	// SQLite passes through untouched.
	s := &dbx{dia: DialectSQLite}
	if s.sql(`a = ? AND t.dns_record`) != `a = ? AND t.dns_record` {
		t.Fatalf("SQLite passthrough broken")
	}
}

func TestAsStrNormalization(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{"2026-11-26T00:00:00Z", "2026-11-26T00:00:00Z"},
		{[]byte(`{"a":1}`), `{"a":1}`},
		{time.Date(2026, 11, 26, 12, 30, 0, 0, time.UTC), "2026-11-26T12:30:00Z"},
	}
	for _, c := range cases {
		if got := asStr(c.in); got != c.want {
			t.Errorf("asStr(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
