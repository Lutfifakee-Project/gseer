// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package storage contains the GSEER persistence layer.  The v0.0.1
// implementation is PostgreSQL-only (ADR-0016: no embedded DB).
//
// M1: package skeleton only (this doc.go).  M3 lands the pgx pool,
// golang-migrate runner (one transaction per migration), and the
// migration set v1 (assets, services, observations, helper views,
// data_sources, source_checkpoints, ingestion_dead_letter, scopes,
// collection_jobs, suppressions, schema_migrations).  M4 lands the
// repository types (Asset, Service, Observation with provenance) and
// the search_index union view.
//
// The storage package is read-side for search (the union view is queried
// by the planner) and write-side for ingestion (v0.0.2+).  No storage
// code imports any egress package.
package storage
