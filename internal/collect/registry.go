// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package collect

// registry.go — the built-in connector registry.  Each connector file
// registers itself via register() in init(); the runner looks connectors
// up by the data_sources.connector value.  Registering the same kind
// twice is a programming error (panic at startup, never at runtime).

var registry = map[string]Collector{}

// register adds one built-in connector.
func register(c Collector) {
	if _, dup := registry[c.Kind()]; dup {
		panic("collect: duplicate connector kind " + c.Kind())
	}
	registry[c.Kind()] = c
}

// Registry returns a copy of the built-in connector registry keyed by
// connector kind.  Review verdicts live with the connectors (see
// docs/SOURCES.md for the full review register).
func Registry() map[string]Collector {
	out := make(map[string]Collector, len(registry))
	for k, v := range registry {
		out[k] = v
	}
	return out
}
