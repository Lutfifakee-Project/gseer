// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package ast holds the typed GQL tree + visitor + explain rendering.
//
// M1: package skeleton only (this doc.go).  M8 lands the node types
// (Or/And/Not/Comparison/Exists/Quantified{ANY,ALL}) carrying canonical
// field paths after alias rewrite, node-count/depth accounting (K-13
// limits enforced at parse), stable canonical String() used by --explain,
// and the visitor for validator/planner.
package ast
