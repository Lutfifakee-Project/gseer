// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package fixture implements the labeled synthetic dataset (SPEC-04 §9)
// and the banner constant shared by CLI/API/Dashboard.
//
// Every row is `provenance=fixture`; every surface marks fixture rows
// with the banner.  Fixture data can never be promoted to real (AC-9.7.x).
//
// M4: this package now carries the full fixture machinery — the
// embedded SPEC-04 §9 corpus (testdata/fixture/corpus.json), the Banner
// constant, and the Facts/Load loader that ingests it through the M4
// store (idempotent via L1/L2).  The QS-6 --load-fixtures /
// --purge-fixtures confirmation gate lives in the CLI layer; the
// provenance=fixture tag is stamped here and can never be promoted to
// real.
package fixture
