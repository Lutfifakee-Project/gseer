// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package observe

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"strconv"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/suppress"
)

// facts.go — the fact shapes both observers produce, through the SAME
// ingestion path as every other writer (Store.IngestFacts → suppression
// gate → L1/L2 idempotency).
//
// A scan of "name.example (hostname) at ip:port" produces:
//
//	fact 1  hostname asset-level fact (the observed identity; no
//	        service row — a name is not a service), evidence notes the
//	        resolved address and the acting scope;
//	fact 2  the endpoint fact: the IP asset + the service row
//	        (asset_id, port, tcp, protocol) + the observation carrying
//	        the observer's provenance, the timestamp and the evidence.
//
// An IP-literal target produces only fact 2.  Nothing is invented:
// evidence holds exactly what the target answered (or the failure).

// scanFacts builds the observation facts for one scan run.  The
// identity contract mirrors the collector runner exactly:
//   - Observation.ID is CALLER-ASSIGNED (the column has no sequence
//     default): fnv1a-64 over "observe:<source_id>:<cursor>", positive
//     BIGINT, a bookkeeping id only — L1 is the idempotency key;
//   - Asset.Sources is stamped with the source name or the sources
//     facet / search_index projection / `gseer host` miss the asset.
func scanFacts(
	now time.Time,
	sourceID int64,
	sourceName string,
	provenance string,
	host string,
	ip netip.Addr,
	port int,
	serviceProtocol string,
	evidence map[string]any,
	scopeID int64,
) []storage.Fact {
	// The gateway already validated this address; its String() form is
	// the canonical text (NormalizeIP would accept it unchanged).
	ipValue := ip.String()
	observed := now.UTC().Truncate(time.Microsecond)
	evidence["scan"].(map[string]any)["scope_id"] = scopeID

	cursor := fmt.Sprintf("%s:%s:%d:%d", provenance, ipValue, port, now.UnixNano())
	obsID := scanObservationID(sourceID, cursor)

	// fact 2 — the endpoint fact (always produced).
	endpoint := storage.Fact{
		Asset: storage.Asset{
			Kind:    storage.AssetKindIP,
			Value:   ipValue,
			IP:      &ipValue,
			Sources: []string{sourceName},
		},
		Service: &storage.Service{
			Port:      port,
			Transport: "tcp",
			Protocol:  serviceProtocol,
		},
		Observation: storage.Observation{
			ID:           obsID,
			SourceID:     sourceID,
			ObservedAt:   observed,
			PayloadHash:  payloadHashHex(evidence),
			SourceCursor: cursor,
			Provenance:   provenance,
			Evidence:     evidence,
		},
	}
	out := []storage.Fact{endpoint}

	// fact 1 — the hostname identity fact (only for hostname targets;
	// a hostname is not an IP and never becomes one).
	if host != ipValue && host != "" {
		hostValue, err := suppress.NormalizeDomain(host)
		if err == nil && hostValue != "" {
			assetKind := storage.AssetKindHostname
			hostCopy := hostValue
			// A bare registrable name (no dot) is a domain asset; a name
			// WITH a dot is a hostname.  Same rule as the dns connector's
			// seed recording.
			if !stringsContainsByte(hostValue, '.') {
				assetKind = storage.AssetKindDomain
			}
			hostEvidence := map[string]any{
				"scan": map[string]any{
					"scope_id":    scopeID,
					"result":      "observed",
					"resolved_ip": ipValue,
					"target":      hostValue + ":" + strconv.Itoa(port),
				},
				"confidence": "high",
			}
			out = append(out, storage.Fact{
				Asset: storage.Asset{
					Kind:     assetKind,
					Value:    hostValue,
					Hostname: &hostCopy,
					Sources:  []string{sourceName},
				},
				Service: nil,
				Observation: storage.Observation{
					ID:           scanObservationID(sourceID, cursor+":name"),
					SourceID:     sourceID,
					ObservedAt:   observed,
					PayloadHash:  payloadHashHex(hostEvidence),
					SourceCursor: cursor + ":name",
					Provenance:   provenance,
					Evidence:     hostEvidence,
				},
			})
		}
	}
	return out
}

func stringsContainsByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

// scanObservationID mirrors the collector runner's caller-assigned
// observation id: fnv1a-64 over "observe:<source_id>:<cursor>"
// (collisions land in the L1/L2 dedupe path, never in correctness).
func scanObservationID(sourceID int64, cursor string) int64 {
	h := fnv.New64a()
	_, _ = fmt.Fprintf(h, "observe:%d:%s", sourceID, cursor)
	return int64(h.Sum64() & 0x7fff_ffff_ffff_ffff)
}
