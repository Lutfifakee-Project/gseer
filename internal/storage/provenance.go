// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package storage

// provenance.go — canonical provenance constants shared by storage,
// fixture loader and CLI (QS-6).
//
// Provenance is the honesty surface of the dataset: every observation is
// labeled with where it came from, and the labeled-synthetic fixture data
// can never be promoted to real internet data.  Keeping the literals in
// one place prevents the "fixture" tag from drifting between the loader,
// the purge paths and the search-side provenance filters.

// FixtureSourceName is the data_sources.name of the labeled synthetic
// fixture source (D-M3-1: the fixture source is itself a registry row).
const FixtureSourceName = "fixture"

// ProvenanceFixture is the observations.provenance value for every row
// written by the fixture loader; it can never be promoted to real (QS-6).
const ProvenanceFixture = "fixture"
