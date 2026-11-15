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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// store.go — the local index directory: state tracking + the atomic
// install with one-generation rollback (trust-chain step 5).
//
// Layout inside Dir (default ~/.gseer/index):
//
//	gseer-index.db        the installed snapshot (SQLite, 0600)
//	gseer-index.db.prev   the previous snapshot (kept for rollback)
//	gseer-index.db.staging  the download/verify staging file (transient)
//	manifest.json         the signed manifest bytes (0600)
//	state.json            the local sequence/check bookkeeping (0600)
//
// Install is atomic in the rename sense: the staged file is fully
// written, verified, fsynced, and only then renamed over the current
// index; the previous index is preserved as .prev.  A failure before
// the final rename leaves the previous state untouched; a failure
// after moving the current file aside restores it.

const (
	SnapshotName    = "gseer-index.db"
	SnapshotPrev    = "gseer-index.db.prev"
	SnapshotStaging = "gseer-index.db.staging"
	ManifestName    = "manifest.json"
	StateName       = "state.json"
)

// LocalState is the persisted bookkeeping for the installed index.
type LocalState struct {
	Sequence    int64     `json:"sequence"`
	BuiltAt     time.Time `json:"built_at"`
	ArtifactSHA string    `json:"artifact_sha256"`
	CheckedAt   time.Time `json:"checked_at"`
	InstalledAt time.Time `json:"installed_at,omitempty"`
	Imported    bool      `json:"imported"`
	ManifestURL string    `json:"manifest_url"`
}

// LoadState reads state.json (nil when absent — a fresh install).
func LoadState(dir string) (*LocalState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, StateName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errf(CodeState, "cannot read the local index state", err.Error(),
			"check the index directory permissions; or remove "+filepath.Join(dir, StateName)+" to re-initialize", err)
	}
	var st LocalState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, errf(CodeState, "the local index state is corrupt", err.Error(),
			"remove "+filepath.Join(dir, StateName)+" and re-run: gseer index update", err)
	}
	return &st, nil
}

// SaveState writes state.json (0600).
func SaveState(dir string, st *LocalState) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errf(CodeState, "cannot create the index directory", err.Error(), "", err)
	}
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return errf(CodeState, "cannot encode the index state", err.Error(), "", err)
	}
	if werr := os.WriteFile(filepath.Join(dir, StateName), raw, 0o600); werr != nil {
		return errf(CodeState, "cannot write the index state", werr.Error(), "", werr)
	}
	return nil
}

// LoadManifest reads the installed manifest bytes (nil when absent).
func LoadManifest(dir string) (*Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, errf(CodeState, "cannot read the installed manifest", err.Error(), "", err)
	}
	return ParseManifest(raw)
}

// InstallSnapshot performs the verified atomic install of a validated
// snapshot: the CALLER has already written the payload to the staging
// file, verified signature + checksum + snapshot validity, and fsynced
// it; this function moves it into place atomically (current→prev,
// staging→current) and persists the manifest + state.  A failure before
// the final rename leaves the previous state untouched; a failure after
// moving the current file aside restores it.
func InstallSnapshot(dir, staging string, m *Manifest, signedManifest []byte, manifestURL string, now time.Time) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errf(CodeState, "cannot create the index directory", err.Error(), "", err)
	}
	current := filepath.Join(dir, SnapshotName)
	prev := filepath.Join(dir, SnapshotPrev)
	// 2. Preserve the current snapshot (one-generation rollback).
	hadCurrent := false
	if _, err := os.Stat(current); err == nil {
		hadCurrent = true
		if rerr := os.Rename(current, prev); rerr != nil {
			_ = os.Remove(staging)
			return errf(CodeState, "cannot preserve the previous snapshot", rerr.Error(), "", rerr)
		}
	}

	// 3. Atomic rename into place; on failure, restore the previous file.
	if rerr := os.Rename(staging, current); rerr != nil {
		if hadCurrent {
			_ = os.Rename(prev, current) // best-effort restore
		}
		_ = os.Remove(staging)
		return errf(CodeState, "cannot install the snapshot", rerr.Error(), "", rerr)
	}

	// 4. Persist the signed manifest next to the snapshot (0600 — the
	//    index holds operator-visible internet data).
	if werr := os.WriteFile(filepath.Join(dir, ManifestName), signedManifest, 0o600); werr != nil {
		return errf(CodeState, "cannot write the installed manifest", werr.Error(), "", werr)
	}

	// 5. Bookkeeping.
	st := &LocalState{
		Sequence:    m.Sequence,
		BuiltAt:     m.BuiltAt,
		ArtifactSHA: m.Artifact.SHA256,
		CheckedAt:   now,
		InstalledAt: now,
		Imported:    false,
		ManifestURL: manifestURL,
	}
	if serr := SaveState(dir, st); serr != nil {
		return serr
	}
	return nil
}

// MarkImported flips the state's Imported flag after a successful (or
// attempted) import so `gseer index status` can report honestly.
func MarkImported(dir string, imported bool, now time.Time) error {
	st, err := LoadState(dir)
	if err != nil || st == nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("index: no local state to mark")
	}
	st.Imported = imported
	st.CheckedAt = now
	return SaveState(dir, st)
}

// syncFile fsyncs a regular file (best-effort durability before the
// atomic rename; the update package's dirsync does the same for the
// binary replacement).
func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return f.Sync()
}
