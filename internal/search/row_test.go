// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package search

// row_test.go — unit tests for the projection pruning + tabular cell
// rendering introduced by the v0.3.2-r2 owner finding (a custom
// projection must never zero the mandatory identity/metadata block).

import (
	"reflect"
	"testing"
	"time"
)

var (
	tPrune0 = time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	tPrune1 = time.Date(2026, 1, 16, 12, 30, 0, 0, time.UTC)
)

func pruneFixtureRow() Row {
	ip := "198.51.100.10"
	org := "AS64512 MATRIX-VANNET"
	tls := "TLS 1.3"
	return Row{
		RowID: 7, RowKind: "service", AssetID: 3,
		AssetKind: "ip", AssetValue: ip,
		IP: &ip, Domain: nil, ASN: nil, ASNOrg: &org,
		Port:      intPtr(443),
		Transport: strPtr("tcp"), Protocol: strPtr("https"),
		Product:      strPtr("nginx"),
		TLSVersion:   &tls,
		Technologies: []string{"nginx", "php"},
		Sources:      []string{"fixture", "dataset"},
		FirstSeen:    tPrune0,
		LastSeen:     tPrune1,
		ObservedAt:   &tPrune1,
	}
}

func strPtr(s string) *string { return &s }
func intPtr(i int) *int       { return &i }

func TestPruneToProjectionKeepsMandatoryAndSelected(t *testing.T) {
	rows := []Row{pruneFixtureRow()}
	PruneToProjection(rows, []string{"ip", "port"})
	r := rows[0]

	// Mandatory identity/metadata block untouched.
	if r.RowID != 7 || r.RowKind != "service" || r.AssetID != 3 ||
		r.AssetKind != "ip" || r.AssetValue != "198.51.100.10" {
		t.Errorf("mandatory identity block corrupted: %+v", r)
	}
	if r.FirstSeen != tPrune0 || r.LastSeen != tPrune1 {
		t.Errorf("mandatory metadata corrupted: %+v", r)
	}
	if r.ObservedAt == nil {
		t.Errorf("observed_at must survive pruning (NULL-able, never fabricated)")
	}
	// Requested fields kept.
	if r.IP == nil || *r.IP != "198.51.100.10" || r.Port == nil || *r.Port != 443 {
		t.Errorf("selected fields lost: ip=%v port=%v", r.IP, r.Port)
	}
	// Unrequested optional fields pruned (nil, not zero-valued).
	if r.ASNOrg != nil || r.Transport != nil || r.Protocol != nil ||
		r.Product != nil || r.TLSVersion != nil ||
		r.Technologies != nil || r.Sources != nil {
		t.Errorf("unrequested columns leaked: %+v", r)
	}
}

func TestPruneAcceptsCanonicalPaths(t *testing.T) {
	rows := []Row{pruneFixtureRow()}
	PruneToProjection(rows, []string{"tls.version"})
	r := rows[0]
	if r.TLSVersion == nil || *r.TLSVersion != "TLS 1.3" {
		t.Errorf("canonical-path field lost: %v", r.TLSVersion)
	}
	if r.IP != nil || r.Port != nil {
		t.Errorf("unrequested fields leaked after path spelling: %+v", r)
	}
}

func TestPruneNoopOnDefaultProjection(t *testing.T) {
	rows := []Row{pruneFixtureRow()}
	want := pruneFixtureRow()
	PruneToProjection(rows, nil)
	if !reflect.DeepEqual(rows[0], want) {
		t.Errorf("default projection must be untouched")
	}
	PruneToProjection(rows, []string{})
	if !reflect.DeepEqual(rows[0], want) {
		t.Errorf("empty fields must be a no-op")
	}
}

func TestVisibleColumns(t *testing.T) {
	got := VisibleColumns([]string{"ip", "port"})
	want := []string{
		"row_id", "row_kind", "asset_id", "asset_kind", "asset_value",
		"ip", "port",
		"first_seen", "last_seen", "observed_at", "stale",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("VisibleColumns:\n got %v\nwant %v", got, want)
	}
	if got := VisibleColumns(nil); got != nil {
		t.Errorf("default projection must render all columns, got %v", got)
	}
}

func TestRowCSVCell(t *testing.T) {
	r := pruneFixtureRow()
	cases := map[string]string{
		"row_id":       "7",
		"row_kind":     "service",
		"asset_id":     "3",
		"asset_kind":   "ip",
		"asset_value":  "198.51.100.10",
		"ip":           "198.51.100.10",
		"port":         "443",
		"asn_org":      "AS64512 MATRIX-VANNET",
		"tls_version":  "TLS 1.3",
		"technologies": "nginx,php",
		"sources":      "fixture,dataset",
		"first_seen":   "2026-01-15T00:00:00Z",
		"last_seen":    "2026-01-16T12:30:00Z",
		"observed_at":  "2026-01-16T12:30:00Z",
		"stale":        "false",
		"domain":       "", // NULL → empty cell
	}
	for col, want := range cases {
		if got := r.CSVCell(col); got != want {
			t.Errorf("CSVCell(%q) = %q, want %q", col, got, want)
		}
	}
	// NULL-able time and stale=true variants.
	r.ObservedAt = nil
	if got := r.CSVCell("observed_at"); got != "" {
		t.Errorf("NULL observed_at must render empty, got %q", got)
	}
	r.Stale = true
	if got := r.CSVCell("stale"); got != "true" {
		t.Errorf("stale=true must render \"true\", got %q", got)
	}
}
