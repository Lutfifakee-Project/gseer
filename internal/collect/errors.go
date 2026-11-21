// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package collect

import "github.com/Lutfifakee-Project/gseer/internal/storage"

// Fact aliases the storage-level ingest unit so connector code and the
// runner read naturally ([]storage.Fact IS []Fact — identical alias).
type Fact = storage.Fact

// FatalError marks a connector error that retries cannot fix (a refused
// query, a malformed request).  Wrap at the point the failure is known
// permanent; the runner's retry loop passes it through unwrapped.
type FatalError struct{ Err error }

func (e FatalError) Error() string { return e.Err.Error() }

// Unwrap gives errors.Is/As access to the wrapped cause.
func (e FatalError) Unwrap() error { return e.Err }

// Fatal wraps err into a FatalError (nil passes through).
func Fatal(err error) error {
	if err == nil {
		return nil
	}
	return FatalError{Err: err}
}
