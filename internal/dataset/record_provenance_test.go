// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package dataset

// record_provenance_test.go — R4 P1-9: dataset records MUST preserve
// the provenance contract end to end — source, connector, provenance,
// observed_at, payload_hash and the bounded evidence land in the
// ingested fact unchanged.  A producer that drops one of these breaks
// the honesty surface this field guards.

import (
	"testing"
	"time"
)

// TestBuildFactPreservesProvenanceContract pins the record → fact
// mapping for every contract field.
func TestBuildFactPreservesProvenanceContract(t *testing.T) {
	observedAt := time.Date(2026, 6, 1, 9, 0, 0, 0, time.UTC)
	rec := &Record{
		Schema: SchemaVersion,
		Asset:  RecordAsset{Kind: "ip", Value: "93.184.216.34", IP: strPtr("93.184.216.34")},
		Service: &RecordService{Port: 443, Transport: "tcp", Protocol: "https",
			Name: "https", Product: "nginx", Version: "1.25.0"},
		Observation: RecordObservation{
			Source:      "central-scan",
			Connector:   "scan-tls",
			Provenance:  "scan-tls",
			ObservedAt:  observedAt,
			PayloadHash: "sha256:provenance-contract",
			Evidence: map[string]any{
				"tls": map[string]any{"version": "TLS 1.3"}, // bounded evidence rides along
			},
		},
	}
	fact, err := buildFact(rec, 1, 33)
	if err != nil {
		t.Fatalf("buildFact: %v", err)
	}

	if fact.Observation.PayloadHash != "sha256:provenance-contract" {
		t.Errorf("payload_hash not preserved: %q", fact.Observation.PayloadHash)
	}
	if fact.Observation.Provenance != "scan-tls" {
		t.Errorf("provenance not preserved: %q", fact.Observation.Provenance)
	}
	if !fact.Observation.ObservedAt.Equal(observedAt.UTC()) {
		t.Errorf("observed_at not preserved: %v", fact.Observation.ObservedAt)
	}
	if fact.Observation.Evidence["tls"] == nil {
		t.Error("bounded evidence not preserved")
	}
	if got, ok := fact.Observation.Evidence["dataset_version"]; !ok || got != int64(33) {
		t.Errorf("dataset_version stamp missing/wrong: %v", got)
	}
	// Service identity (the producer's service identification) rides along.
	if fact.Service == nil || fact.Service.Product != "nginx" || fact.Service.Version != "1.25.0" {
		t.Errorf("service product/version not preserved: %+v", fact.Service)
	}
	// Source/connector are resolved by the CALLER through the source
	// registry (ensureRecordSource) — buildFact must not drop the record's
	// own values, which the caller keys the registry on.
	if rec.Observation.Source != "central-scan" || rec.Observation.Connector != "scan-tls" {
		t.Error("record source/connector must stay intact for the registry resolution")
	}
}
