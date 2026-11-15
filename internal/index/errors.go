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

import "fmt"

// Error is the structured shared-index error (the same shape as the
// update package's): a stable E_INDEX_* code plus what failed, why,
// and the exact next step.  Codes are stable across releases so that
// scripts and CI can match on them.
type Error struct {
	Code string // e.g. E_INDEX_UNSIGNED
	What string
	Why  string
	Next string
	Err  error
}

func (e *Error) Error() string {
	out := e.Code + ": " + e.What
	if e.Why != "" {
		out += "\nWhy: " + e.Why
	}
	if e.Next != "" {
		out += "\nTry: " + e.Next
	}
	return out
}

// Unwrap exposes the wrapped cause so errors.Is / errors.As can reach
// it through every layer.
func (e *Error) Unwrap() error { return e.Err }

// Stable E_INDEX_* codes.
const (
	// E_INDEX_UNSIGNED — the manifest carries no signature.
	CodeUnsigned = "E_INDEX_UNSIGNED"
	// E_INDEX_BAD_SIGNATURE — missing/undecodable/failing signature.
	CodeBadSignature = "E_INDEX_BAD_SIGNATURE"
	// E_INDEX_MALFORMED — the manifest is not valid JSON or structurally broken.
	CodeMalformed = "E_INDEX_MALFORMED"
	// E_INDEX_URL — the manifest/artifact URL is not HTTP(S).
	CodeURL = "E_INDEX_URL"
	// E_INDEX_UNREACHABLE — the endpoint did not answer.
	CodeUnreachable = "E_INDEX_UNREACHABLE"
	// E_INDEX_HTTP — the endpoint returned a non-200 status.
	CodeHTTP = "E_INDEX_HTTP"
	// E_INDEX_CHECKSUM — SHA-256 or size mismatch.
	CodeChecksum = "E_INDEX_CHECKSUM"
	// E_INDEX_SIZE — the payload exceeds the size cap.
	CodeSize = "E_INDEX_SIZE"
	// E_INDEX_SCHEMA — the snapshot's schema is incompatible (newer
	// than this build, or not a GSEER snapshot at all).
	CodeSchema = "E_INDEX_SCHEMA"
	// E_INDEX_INTEGRITY — the snapshot failed SQLite integrity_check
	// or the row counts do not match the manifest.
	CodeIntegrity = "E_INDEX_INTEGRITY"
	// E_INDEX_STATE — the local index state cannot be read/written.
	CodeState = "E_INDEX_STATE"
	// E_INDEX_IMPORT — the import into the personal store failed.
	CodeImport = "E_INDEX_IMPORT"
)

func errf(code, what, why, next string, err error) *Error {
	return &Error{Code: code, What: what, Why: why, Next: next, Err: err}
}

// malformedf builds an E_INDEX_MALFORMED with a formatting reason.
func malformedf(what string, args ...any) *Error {
	return &Error{Code: CodeMalformed, What: fmt.Sprintf(what, args...),
		Next: "fetch the official manifest; never apply one that does not parse"}
}
