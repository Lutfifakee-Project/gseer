// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression coverage for the R12 lint remediation refactor of
// upsertPersonalConfig (QS-6/R3 surgical config edit): the split into
// scanPersonalConfigLines / insertMissingDSN / applyMissingBlocks must
// preserve the documented behavior byte-for-byte — in-place profile and
// dsn rewrites, dsn insertion after the block header, block/profile
// backfill, flow-style refusal, dsn quoting and file-mode preservation.

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	return p
}

func readBack(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	return string(raw)
}

func TestUpsertPersonalConfigReplacesInPlace(t *testing.T) {
	path := writeTempConfig(t, ""+
		"# operator header comment\n"+
		"profile: server\n"+
		"search:\n"+
		"  limit: 10\n"+
		"database:\n"+
		"  dsn: 'sqlite:///old/index.db'\n"+
		"  busy_timeout: 5000\n")
	if err := upsertPersonalConfig(path, "sqlite:///home/op/.gseer/index.db"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	want := "" +
		"# operator header comment\n" +
		"profile: personal\n" +
		"search:\n" +
		"  limit: 10\n" +
		"database:\n" +
		"  dsn: 'sqlite:///home/op/.gseer/index.db'\n" +
		"  busy_timeout: 5000\n"
	if got := readBack(t, path); got != want {
		t.Fatalf("byte-for-byte mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestUpsertPersonalConfigInsertsMissingDSNAfterHeader(t *testing.T) {
	path := writeTempConfig(t, "database:\n  busy_timeout: 5000\n")
	if err := upsertPersonalConfig(path, "sqlite:///x/y.db"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	want := "profile: personal\ndatabase:\n  dsn: 'sqlite:///x/y.db'\n  busy_timeout: 5000\n"
	if got := readBack(t, path); got != want {
		t.Fatalf("byte-for-byte mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestUpsertPersonalConfigAppendsMissingBlockAndPrependsProfile(t *testing.T) {
	path := writeTempConfig(t, "search:\n  limit: 10\n")
	if err := upsertPersonalConfig(path, "sqlite:///x/y.db"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// The empty separator line + the append order are the historical
	// single-pass behavior; they are pinned here on purpose.
	want := "profile: personal\nsearch:\n  limit: 10\n\n\ndatabase:\n  dsn: 'sqlite:///x/y.db'"
	if got := readBack(t, path); got != want {
		t.Fatalf("byte-for-byte mismatch\n got: %q\nwant: %q", got, want)
	}
}

func TestUpsertPersonalConfigRefusesFlowStyle(t *testing.T) {
	content := "database: {dsn: 'x'}\n"
	path := writeTempConfig(t, content)
	err := upsertPersonalConfig(path, "sqlite:///x/y.db")
	if err == nil {
		t.Fatal("want the flow-style refusal, got nil")
	}
	if !strings.Contains(err.Error(), "flow-style database mapping") || !strings.Contains(err.Error(), path) {
		t.Fatalf("refusal must name the mapping and the config path, got: %v", err)
	}
	if got := readBack(t, path); got != content {
		t.Fatalf("file must stay untouched on refusal\n got: %q", got)
	}
}

func TestUpsertPersonalConfigPreservesFileMode(t *testing.T) {
	path := writeTempConfig(t, "database:\n")
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	want := st.Mode().Perm() // whatever umask allowed at creation
	if err := upsertPersonalConfig(path, "sqlite:///x/y.db"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	st, err = os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := st.Mode().Perm(); got != want {
		t.Fatalf("file mode changed: want %v, got %v", want, got)
	}
}

func TestUpsertPersonalConfigKeepsDSNIndentation(t *testing.T) {
	path := writeTempConfig(t, "database:\n\tdsn: 'old'\n")
	if err := upsertPersonalConfig(path, "sqlite:///x/y.db"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	want := "profile: personal\ndatabase:\n\tdsn: 'sqlite:///x/y.db'\n"
	if got := readBack(t, path); got != want {
		t.Fatalf("tab indentation must survive\n got: %q\nwant: %q", got, want)
	}
}

func TestUpsertPersonalConfigQuotesDSN(t *testing.T) {
	path := writeTempConfig(t, "database:\n")
	if err := upsertPersonalConfig(path, "sqlite:///o'brien/x.db"); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	want := "profile: personal\ndatabase:\n  dsn: 'sqlite:///o''brien/x.db'\n"
	if got := readBack(t, path); got != want {
		t.Fatalf("single quotes must be YAML-escaped\n got: %q\nwant: %q", got, want)
	}
}
