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
	"net/http"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// update.go — the client orchestration: Check (verify + report, no
// snapshot download) and Update (the full trust chain: verify manifest
// → sequence gate → download → checksum → validate → atomic install →
// import into the personal store).

// Options configures Check/Update.  ManifestURL empty means the
// official channel (the CLI resolves flag/env/config before calling).
type Options struct {
	// ManifestURL is the signed manifest location.
	ManifestURL string
	// Dir is the local index directory.
	Dir string
	// Store, when non-nil, receives the imported snapshot rows
	// (personal profile).  Nil = install only (import skipped; the CLI
	// passes the personal store for the default profile).
	Store *sqlite.Store
	// Force installs even when the remote sequence is not newer (also
	// re-imports — useful after a local restore).
	Force bool
	// Client overrides the HTTP client (tests).
	Client *http.Client
	// Now pins the clock (tests).
	Now func() time.Time
}

// Result reports what a Check/Update did (honest, per-surface).
type Result struct {
	CheckedAt    time.Time  `json:"checked_at"`
	ManifestURL  string     `json:"manifest_url"`
	Remote       *Manifest  `json:"remote,omitempty"`
	RemoteSeq    int64      `json:"remote_sequence"`
	LocalSeq     int64      `json:"local_sequence"`
	UpToDate     bool       `json:"up_to_date"`
	Installed    bool       `json:"installed"`
	Validated    bool       `json:"validated"`
	ImportResult *ImportRes `json:"import,omitempty"`
	Err          error      `json:"-"`
}

// ImportRes is the JSON-friendly import summary (the internal
// ImportResult carries the same fields).
type ImportRes struct {
	AssetsInserted       int64 `json:"assets_inserted"`
	AssetsUpdated        int64 `json:"assets_updated"`
	ServicesInserted     int64 `json:"services_inserted"`
	ServicesUpdated      int64 `json:"services_updated"`
	ObservationsInserted int64 `json:"observations_inserted"`
	ObservationsDeduped  int64 `json:"observations_deduped"`
}

func (o *Options) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now().UTC()
}

// Check fetches and verifies the manifest (signature FIRST — trust
// chain step 1) and reports whether a newer sequence is available.
// No snapshot is downloaded.
func Check(ctx context.Context, opts Options) (*Result, error) {
	res := &Result{CheckedAt: opts.now(), ManifestURL: opts.ManifestURL}
	m, signed, err := fetchVerifiedManifest(ctx, opts, res)
	if err != nil {
		return nil, err
	}
	res.Remote = m
	res.RemoteSeq = m.Sequence
	local, lerr := LoadState(opts.Dir)
	if lerr != nil {
		return nil, lerr
	}
	if local != nil {
		res.LocalSeq = local.Sequence
	}
	res.UpToDate = m.Sequence <= res.LocalSeq
	_ = signed // Check never applies anything
	return res, nil
}

// Update runs the full chain and (when Options.Store is set) imports.
func Update(ctx context.Context, opts Options) (*Result, error) {
	res := &Result{CheckedAt: opts.now(), ManifestURL: opts.ManifestURL}
	m, signed, err := fetchVerifiedManifest(ctx, opts, res)
	if err != nil {
		return nil, err
	}
	res.Remote = m
	res.RemoteSeq = m.Sequence

	local, lerr := LoadState(opts.Dir)
	if lerr != nil {
		return nil, lerr
	}
	if local != nil {
		res.LocalSeq = local.Sequence
	}
	if m.Sequence <= res.LocalSeq && !opts.Force {
		res.UpToDate = true
		if opts.Store != nil && local != nil && !local.Imported && opts.Force == false {
			// Installed but never imported (e.g. the first import
			// failed): import the installed snapshot now.
			ires, ierr := importInstalled(ctx, opts, res, local.Sequence)
			if ierr != nil {
				return nil, ierr
			}
			res.ImportResult = ires
		}
		return res, nil
	}

	// Trust-chain step 3: download + checksum.
	f := &Fetcher{Client: opts.Client}
	artifactURL, rerr := m.ResolveArtifactURL(opts.ManifestURL)
	if rerr != nil {
		return nil, rerr
	}
	payload, ferr := f.Fetch(ctx, artifactURL, MaxSnapshotBytes)
	if ferr != nil {
		return nil, ferr
	}
	if cerr := m.Artifact.VerifyChecksum(payload); cerr != nil {
		return nil, cerr
	}

	// Trust-chain step 4: snapshot validity.  Stage the payload once
	// (fsynced) — the same file the atomic install then renames into
	// place; nothing is installed until validation passes.
	staging := joinPath(opts.Dir, SnapshotStaging)
	if serr := writeFile0600(staging, payload); serr != nil {
		return nil, serr
	}
	if ferr := syncFile(staging); ferr != nil {
		_ = removeFile(staging)
		return nil, errf(CodeState, "cannot fsync the staging snapshot", ferr.Error(), "", ferr)
	}
	if verr := ValidateSnapshot(ctx, staging, m.Counts); verr != nil {
		_ = removeFile(staging)
		return nil, verr
	}
	res.Validated = true

	// Trust-chain step 5: atomic install with one-generation rollback.
	if ierr := InstallSnapshot(opts.Dir, staging, m, signed, opts.ManifestURL, opts.now()); ierr != nil {
		_ = removeFile(staging)
		return nil, ierr
	}
	res.Installed = true

	// Step 6: import into the personal store when configured.
	if opts.Store != nil {
		ires, ierr := runImport(ctx, opts.Store, joinPath(opts.Dir, SnapshotName), m.Sequence)
		if ierr != nil {
			// The snapshot IS installed (search can still be repaired
			// by re-running `gseer index update`); report honestly.
			_ = MarkImported(opts.Dir, false, opts.now())
			res.Err = ierr
			return res, ierr
		}
		res.ImportResult = ires
		_ = MarkImported(opts.Dir, true, opts.now())
	}
	return res, nil
}

// runImport runs ImportSnapshot and maps the result to the
// JSON-friendly summary.
func runImport(ctx context.Context, store *sqlite.Store, snapPath string, seq int64) (*ImportRes, error) {
	ir, err := ImportSnapshot(ctx, store, snapPath, seq)
	if err != nil {
		return nil, err
	}
	return &ImportRes{
		AssetsInserted:       ir.AssetsInserted,
		AssetsUpdated:        ir.AssetsUpdated,
		ServicesInserted:     ir.ServicesInserted,
		ServicesUpdated:      ir.ServicesUpdated,
		ObservationsInserted: ir.ObservationsInserted,
		ObservationsDeduped:  ir.ObservationsDeduped,
	}, nil
}

// importInstalled imports the ALREADY-installed snapshot (the repair
// path for an install whose first import failed).
func importInstalled(ctx context.Context, opts Options, res *Result, seq int64) (*ImportRes, error) {
	ires, ierr := runImport(ctx, opts.Store, joinPath(opts.Dir, SnapshotName), seq)
	if ierr != nil {
		_ = MarkImported(opts.Dir, false, opts.now())
		return nil, ierr
	}
	_ = MarkImported(opts.Dir, true, opts.now())
	res.Installed = true
	return ires, nil
}

// fetchVerifiedManifest fetches the manifest and verifies its
// signature against the trust anchor (steps 1-2 of the trust chain).
func fetchVerifiedManifest(ctx context.Context, opts Options, res *Result) (*Manifest, []byte, error) {
	f := &Fetcher{Client: opts.Client}
	signed, err := f.Fetch(ctx, opts.ManifestURL, MaxManifestBytes)
	if err != nil {
		return nil, nil, err
	}
	m, err := ParseManifest(signed)
	if err != nil {
		return nil, nil, err
	}
	if verr := m.VerifySignature(TrustAnchor()); verr != nil {
		return nil, nil, verr
	}
	return m, signed, nil
}
