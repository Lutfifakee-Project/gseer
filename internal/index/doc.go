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

// Package index implements the v0.3.2 shared-index client (and the
// snapshot export the provider tool reuses).
//
// The approved shared-index architecture (MASTER PROMPT §4, STAGE 3
// approval items 1-3): the project's scheduled pipeline builds a
// VERSIONED, SIGNED SQLite snapshot of the collected internet-asset
// index and publishes it to durable storage (a rolling GitHub release).
// The CLI downloads, verifies, and imports it into the personal store,
// so `gseer search` returns real indexed internet assets without any
// manual collection.
//
// Trust chain (in enforcement order — verification is FIRST, download
// is LAST; mirrors internal/update):
//
//  1. SIGNATURE: the index manifest carries an Ed25519 signature over
//     its canonical core bytes; the public key is EMBEDDED in the
//     binary.  A manifest from any URL is worthless without a valid
//     signature — "never trust an unsigned index simply because it
//     comes from a familiar download URL".
//  2. SEQUENCE: the manifest sequence must be strictly NEWER than the
//     installed one; downgrades and same-sequence re-installs are
//     refused without Force.
//  3. CHECKSUM: the downloaded snapshot must match the manifest's
//     SHA-256 and size exactly.
//  4. SNAPSHOT VALIDITY: the file must pass SQLite integrity_check,
//     carry the expected schema (never NEWER than this build), and
//     contain the row counts the manifest claims.
//  5. ATOMIC INSTALL: the snapshot is written to a staging file NEXT
//     TO the target (same filesystem → rename is atomic), fsynced, then
//     renamed over the current index; the previous snapshot is kept as
//     .prev for one-generation rollback.  A failure at any step leaves
//     the previously installed index intact.
//  6. IMPORT: rows are merged into the personal store through the SAME
//     upsert/dedup contracts live collection uses (L1 delivery identity
//     + L2 payload-hash dedup), so re-importing a snapshot is a no-op
//     and a newer snapshot merges incrementally.
//
// Provenance: every imported observation carries provenance
// "shared-index" and the assets gain a "shared-index" entry in their
// sources list — search results honestly show WHERE each fact came
// from, and a future scoped purge can target exactly these rows.
package index

// FormatVersion is the manifest format this package speaks.  A client
// refuses a manifest whose Format it does not recognize.
const FormatVersion = "gseer-index/1"

// ProvenanceSharedIndex is the observations.provenance label for rows
// imported from the shared index; the asset sources list gains the
// same name.  Search output therefore labels shared-index rows the way
// fixture rows are labeled "fixture" — provenance is never hidden.
const ProvenanceSharedIndex = "shared-index"

// SourceNameSharedIndex is the data_sources row the importer registers
// (connector "index", disabled by default — the pipeline, not this
// process, produces the data).
const SourceNameSharedIndex = "shared-index"

// SourceTermsSharedIndex documents the terms under which the shared
// index rows were collected (the provider pipeline runs only
// reviewed-enabled connectors; see docs/SOURCES.md).
const SourceTermsSharedIndex = "terms:provider-pipeline (reviewed-enabled connectors only; docs/SOURCES.md)"
