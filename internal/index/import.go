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

package index

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// import.go — trust-chain step 6: merging a validated snapshot into
// the personal store.
//
// The import reuses the EXACT contracts live collection uses:
//   - assets/services go through Store.UpsertAsset/UpsertService (the
//     same merge semantics: first_seen preserved, last_seen =
//     GREATEST, stale cleared on a fresh sighting, enrichment
//     COALESCE-merged, suppression backstop enforced);
//   - observations go through Store.InsertObservation with the SAME
//     delivery identity (L1: source_id + source_cursor) and fact
//     identity (L2: payload hash) — so RE-importing the same snapshot
//     is a no-op and a newer snapshot merges incrementally.
//
// Provenance is rewritten to "shared-index" (the record's provenance
// IN THIS STORE — the evidence payload itself is copied verbatim), the
// asset sources list gains a "shared-index" entry, and the snapshot's
// asset/service row ids are remapped to the local ids.  A crash mid-
// import is recoverable: re-running the import is idempotent.

// ImportResult reports what one import did.
type ImportResult struct {
	AssetsInserted       int64
	AssetsUpdated        int64
	ServicesInserted     int64
	ServicesUpdated      int64
	ObservationsInserted int64
	ObservationsDeduped  int64
}

// ImportSnapshot imports the validated snapshot file into the store.
// The caller must have completed trust-chain steps 1-5 (the CLI path
// always does; tests drive this directly).
func ImportSnapshot(ctx context.Context, store *sqlite.Store, snapPath string, sequence int64) (*ImportResult, error) {
	res := &ImportResult{}

	// One registered source for the whole snapshot (connector "index",
	// disabled — this process never collects; it only merges).
	sourceID, err := store.EnsureSource(ctx, SourceNameSharedIndex, "index", SourceTermsSharedIndex, nil)
	if err != nil {
		return nil, errf(CodeImport, "cannot register the shared-index source", err.Error(),
			"check the personal database; retry: gseer index update", err)
	}

	db, err := sqlite.OpenReadOnly(snapPath)
	if err != nil {
		return nil, errf(CodeImport, "cannot open the snapshot for import", err.Error(), "", err)
	}
	defer func() { _ = db.Close() }()

	assetIDs, err := importAssets(ctx, store, db, res)
	if err != nil {
		return nil, err
	}
	serviceIDs, err := importServices(ctx, store, db, assetIDs, res)
	if err != nil {
		return nil, err
	}
	if err := importObservations(ctx, store, db, sourceID, assetIDs, serviceIDs, sequence, res); err != nil {
		return nil, err
	}
	return res, nil
}

// importAssets merges the snapshot assets (L1/L2-equivalent: the store
// upsert keyed on (kind, value)).
func importAssets(ctx context.Context, store *sqlite.Store, db *sql.DB, res *ImportResult) (map[int64]int64, error) {
	rows, err := db.QueryContext(ctx, `
SELECT id, kind, value, ip, domain, hostname, asn, asn_org,
       geo_country, geo_region, geo_city, sources, first_seen, last_seen, stale
FROM assets ORDER BY id`)
	if err != nil {
		return nil, errf(CodeImport, "cannot read the snapshot assets", err.Error(), "", err)
	}
	defer func() { _ = rows.Close() }()

	ids := make(map[int64]int64)
	for rows.Next() {
		var (
			id, asn                      int64
			kind, value                  string
			ip, domain, hostname         sql.NullString
			asnOrg                       sql.NullString
			geoCountry, geoRegion, geoCi sql.NullString
			sourcesJSON                  sql.NullString
			firstSeen, lastSeen          string
			staleInt                     int64
		)
		if err := rows.Scan(&id, &kind, &value, &ip, &domain, &hostname, &asn, &asnOrg,
			&geoCountry, &geoRegion, &geoCi, &sourcesJSON, &firstSeen, &lastSeen, &staleInt); err != nil {
			return nil, errf(CodeImport, "cannot scan a snapshot asset", err.Error(), "", err)
		}
		a := &storage.Asset{
			Kind:       storage.AssetKind(kind),
			Value:      value,
			ASNOrg:     nullStr(asnOrg),
			GeoCountry: nullStr(geoCountry),
			GeoRegion:  nullStr(geoRegion),
			GeoCity:    nullStr(geoCi),
			Sources:    append(decodeSources(sourcesJSON), ProvenanceSharedIndex),
			Stale:      staleInt != 0,
		}
		if kind == string(storage.AssetKindIP) {
			a.IP = nullPtr(ip)
		}
		if kind == string(storage.AssetKindDomain) {
			a.Domain = nullPtr(domain)
		}
		if kind == string(storage.AssetKindHostname) {
			a.Hostname = nullPtr(hostname)
		}
		a.ASN = int(asn)
		if a.FirstSeen, err = sqlite.ParseTS(firstSeen); err != nil {
			return nil, errf(CodeImport, "cannot parse a snapshot asset timestamp", fmt.Sprintf("%s: %v", firstSeen, err), "", err)
		}
		if a.LastSeen, err = sqlite.ParseTS(lastSeen); err != nil {
			return nil, errf(CodeImport, "cannot parse a snapshot asset timestamp", fmt.Sprintf("%s: %v", lastSeen, err), "", err)
		}
		localID, inserted, uerr := store.UpsertAsset(ctx, a)
		if uerr != nil {
			return nil, errf(CodeImport, "cannot merge a snapshot asset", fmt.Sprintf("%s %q: %v", kind, value, uerr), "", uerr)
		}
		ids[id] = localID
		if inserted {
			res.AssetsInserted++
		} else {
			res.AssetsUpdated++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errf(CodeImport, "cannot iterate the snapshot assets", err.Error(), "", err)
	}
	return ids, nil
}

// importServices merges the snapshot services with remapped asset ids.
func importServices(ctx context.Context, store *sqlite.Store, db *sql.DB, assetIDs map[int64]int64, res *ImportResult) (map[int64]int64, error) {
	rows, err := db.QueryContext(ctx, `
SELECT id, asset_id, port, transport, protocol, name, product, version,
       first_seen, last_seen, stale
FROM services ORDER BY id`)
	if err != nil {
		return nil, errf(CodeImport, "cannot read the snapshot services", err.Error(), "", err)
	}
	defer func() { _ = rows.Close() }()

	ids := make(map[int64]int64)
	for rows.Next() {
		var (
			id, assetID         int64
			port                int64
			transport, protocol string
			name, product, vers sql.NullString
			firstSeen, lastSeen string
			staleInt            int64
		)
		if err := rows.Scan(&id, &assetID, &port, &transport, &protocol, &name, &product, &vers,
			&firstSeen, &lastSeen, &staleInt); err != nil {
			return nil, errf(CodeImport, "cannot scan a snapshot service", err.Error(), "", err)
		}
		localAsset, ok := assetIDs[assetID]
		if !ok {
			return nil, errf(CodeImport, "snapshot service references an unknown asset",
				fmt.Sprintf("service %d -> asset %d", id, assetID), "", nil)
		}
		sv := &storage.Service{
			AssetID:   localAsset,
			Port:      int(port),
			Transport: transport,
			Protocol:  protocol,
			Name:      nullStr(name),
			Product:   nullStr(product),
			Version:   nullStr(vers),
			Stale:     staleInt != 0,
		}
		if sv.FirstSeen, err = sqlite.ParseTS(firstSeen); err != nil {
			return nil, errf(CodeImport, "cannot parse a snapshot service timestamp", fmt.Sprintf("%s: %v", firstSeen, err), "", err)
		}
		if sv.LastSeen, err = sqlite.ParseTS(lastSeen); err != nil {
			return nil, errf(CodeImport, "cannot parse a snapshot service timestamp", fmt.Sprintf("%s: %v", lastSeen, err), "", err)
		}
		localID, inserted, uerr := store.UpsertService(ctx, sv)
		if uerr != nil {
			return nil, errf(CodeImport, "cannot merge a snapshot service", fmt.Sprintf("service %d: %v", id, uerr), "", uerr)
		}
		ids[id] = localID
		if inserted {
			res.ServicesInserted++
		} else {
			res.ServicesUpdated++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errf(CodeImport, "cannot iterate the snapshot services", err.Error(), "", err)
	}
	return ids, nil
}

// importObservations merges the snapshot observations (L1 delivery
// identity + L2 fact identity, remapped ids, provenance rewritten to
// "shared-index"; evidence copied verbatim).
func importObservations(ctx context.Context, store *sqlite.Store, db *sql.DB,
	sourceID int64, assetIDs, serviceIDs map[int64]int64, sequence int64, res *ImportResult) error {
	rows, err := db.QueryContext(ctx, `
SELECT asset_id, service_id, observed_at, payload_hash, source_cursor, evidence
FROM observations ORDER BY id`)
	if err != nil {
		return errf(CodeImport, "cannot read the snapshot observations", err.Error(), "", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			assetID      int64
			serviceID    sql.NullInt64
			observedAt   string
			payloadHash  string
			sourceCursor string
			evidenceJSON sql.NullString
		)
		if err := rows.Scan(&assetID, &serviceID, &observedAt, &payloadHash, &sourceCursor, &evidenceJSON); err != nil {
			return errf(CodeImport, "cannot scan a snapshot observation", err.Error(), "", err)
		}
		localAsset, ok := assetIDs[assetID]
		if !ok {
			return errf(CodeImport, "snapshot observation references an unknown asset",
				fmt.Sprintf("observation cursor %q -> asset %d", sourceCursor, assetID), "", nil)
		}
		o := &storage.Observation{
			SourceID:     sourceID,
			AssetID:      localAsset,
			ObservedAt:   time.Time{},
			PayloadHash:  payloadHash,
			SourceCursor: fmt.Sprintf("idx:%d:%s", sequence, sourceCursor),
			Provenance:   ProvenanceSharedIndex,
		}
		o.ID = importObservationID(sourceID, o.SourceCursor)
		if serviceID.Valid {
			localService, ok := serviceIDs[serviceID.Int64]
			if !ok {
				return errf(CodeImport, "snapshot observation references an unknown service",
					fmt.Sprintf("observation cursor %q -> service %d", sourceCursor, serviceID.Int64), "", nil)
			}
			o.ServiceID = &localService
		}
		if o.ObservedAt, err = sqlite.ParseTS(observedAt); err != nil {
			return errf(CodeImport, "cannot parse a snapshot observation timestamp", fmt.Sprintf("%s: %v", observedAt, err), "", err)
		}
		if evidenceJSON.Valid && evidenceJSON.String != "" {
			ev := map[string]any{}
			if jerr := json.Unmarshal([]byte(evidenceJSON.String), &ev); jerr == nil {
				o.Evidence = ev
			}
			// An evidence payload that does not parse stays out of the
			// in-memory map; the row still imports (L1/L2 identity does
			// not depend on the evidence map) — never fail the import
			// over a foreign evidence quirk.
		}
		_, inserted, ierr := store.InsertObservation(ctx, o)
		if ierr != nil {
			return errf(CodeImport, "cannot merge a snapshot observation",
				fmt.Sprintf("cursor %q: %v", o.SourceCursor, ierr), "", ierr)
		}
		if inserted {
			res.ObservationsInserted++
		} else {
			res.ObservationsDeduped++
		}
	}
	if err := rows.Err(); err != nil {
		return errf(CodeImport, "cannot iterate the snapshot observations", err.Error(), "", err)
	}
	return nil
}

func nullStr(v sql.NullString) string {
	if v.Valid {
		return v.String
	}
	return ""
}

// importObservationID derives the caller-assigned observations.id —
// fnv1a-64 over the delivery identity, the SAME scheme the collect
// runner uses (a bookkeeping id only: L1 (source_id, source_cursor) is
// the idempotency key, and the ON CONFLICT DO NOTHING insert falls back
// to the L2 fact identity).
func importObservationID(sourceID int64, cursor string) int64 {
	h := fnv.New64a()
	// The hash writer is an in-memory sink: Fprintf cannot fail, but the
	// error is discarded explicitly for errcheck.
	_, _ = fmt.Fprintf(h, "index:%d:%s", sourceID, cursor)
	// Same scheme as the collect runner's observation id (internal/collect
	// runner.go): the sign bit is masked so the int64 cast is a positive,
	// overflow-free BIGINT (gosec G115).
	return int64(h.Sum64() & 0x7fff_ffff_ffff_ffff)
}

func nullPtr(v sql.NullString) *string {
	if v.Valid && v.String != "" {
		s := v.String
		return &s
	}
	return nil
}

// decodeSources parses the snapshot's JSON sources array (missing or
// malformed values degrade to an empty list — the "shared-index" label
// is always appended by the caller).
func decodeSources(v sql.NullString) []string {
	if !v.Valid || v.String == "" {
		return nil
	}
	var out []string
	if err := json.Unmarshal([]byte(v.String), &out); err != nil {
		return nil
	}
	return out
}
