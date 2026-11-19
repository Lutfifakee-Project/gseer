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

package cli

// personal_dbpath_test.go — Rev16 regression tests for the personal
// database default location and the safe legacy migration.
//
// Owner-acceptance finding: the database ended up at
// /tmp/asdlc-rollback/store.db — the v0.3.1-era shared-index acceptance
// scripts seed $GSEER_HOME/store.db and a harness pointed GSEER_HOME at
// a recycled tmpfs.  The Rev16 contract pinned here:
//
//   1. with NO environment overrides the default DB lives in the
//      persistent XDG state directory ($XDG_STATE_HOME/gseer, falling
//      back to $HOME/.local/state/gseer) — structurally never /tmp;
//   2. an explicit GSEER_HOME (portable install) is respected verbatim,
//      with a visible warning when it points under the OS temp dir;
//   3. an explicit config DSN / --db-path always wins;
//   4. a pre-Rev16 default database is IMPORTED (copied + byte-verified)
//      once, the original is never modified or deleted, and the note in
//      the output spells out the rollback;
//   5. a failed import leaves the pre-call state fully intact (inline
//      rollback, no staged leftovers).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("GSEER_CONFIG", "")
	t.Setenv("GSEER_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	t.Cleanup(func() { flags.configPath = ""; flags.quiet = false; flags.profile = "" })
	flags.configPath, flags.quiet, flags.profile = "", false, ""
	return home
}

// TestDefaultPersonalDBPathResolutionMatrix pins the full resolution
// order: explicit GSEER_HOME > XDG_STATE_HOME > $HOME/.local/state.
func TestDefaultPersonalDBPathResolutionMatrix(t *testing.T) {
	home := fakeHome(t)

	// (1) No overrides: XDG fallback inside HOME — persistent, portable,
	// and structurally never /tmp-derived.  The host's HOME here IS a
	// t.TempDir (which lives under /tmp), so "not under /tmp" is proved
	// structurally instead: TMPDIR is set to a sentinel and the resolved
	// path must not move — the resolution never consults the OS temp dir.
	t.Setenv("TMPDIR", "/gseer-sentinel-not-tmp")
	want := filepath.Join(home, ".local", "state", "gseer", "gseer.db")
	got := defaultPersonalDBPath()
	if got != want {
		t.Errorf("no-env default = %q, want %q (and it must not follow TMPDIR)", got, want)
	}
	if strings.Contains(got, "gseer-sentinel-not-tmp") {
		t.Errorf("the default database path must never derive from TMPDIR, got %q", got)
	}

	// (2) XDG_STATE_HOME set (absolute): wins over the HOME fallback.
	xdg := t.TempDir()
	t.Setenv("XDG_STATE_HOME", xdg)
	want = filepath.Join(xdg, "gseer", "gseer.db")
	if got := defaultPersonalDBPath(); got != want {
		t.Errorf("XDG_STATE_HOME default = %q, want %q", got, want)
	}

	// (3) XDG spec: a RELATIVE XDG_STATE_HOME is invalid and ignored.
	t.Setenv("XDG_STATE_HOME", "relative/xdg")
	want = filepath.Join(home, ".local", "state", "gseer", "gseer.db")
	if got := defaultPersonalDBPath(); got != want {
		t.Errorf("relative XDG_STATE_HOME must be ignored: got %q, want %q", got, want)
	}

	// (4) GSEER_HOME (explicit portable install): respected verbatim, and
	// it wins over XDG — the override is the operator's choice.
	gh := t.TempDir()
	t.Setenv("GSEER_HOME", gh)
	t.Setenv("XDG_STATE_HOME", xdg)
	want = filepath.Join(gh, "gseer.db")
	if got := defaultPersonalDBPath(); got != want {
		t.Errorf("GSEER_HOME default = %q, want %q", got, want)
	}
}

// TestVolatileDBPathWarning pins the honest warning: an explicit path
// under the OS temp dir earns a note (non-fatal — the override stands),
// while persistent paths stay silent.
func TestVolatileDBPathWarning(t *testing.T) {
	// A path outside the OS temp dir must stay silent (choose a fixed
	// persistent-style path — the check is structural and does not stat).
	if got := volatileDBPathNote("/home/gseer-portability-fixture/gseer.db"); got != "" {
		t.Errorf("a persistent path must not earn a volatile warning, got: %s", got)
	}
	// The owner-acceptance finding, verbatim shape: a path under the OS
	// temp directory must earn the note (non-fatal; the override stands).
	inside := filepath.Join(os.TempDir(), "asdlc-rollback", "store.db")
	if got := volatileDBPathNote(inside); got == "" {
		t.Errorf("a path under %s must earn the volatile warning (the /tmp/asdlc-rollback finding)", os.TempDir())
	}
}

// TestImportLegacyPersonalDB verifies the safe migration mechanics:
// copy + byte verification + atomic rename, source untouched, target
// never overwritten, no staged leftovers on any path.
func TestImportLegacyPersonalDB(t *testing.T) {
	home := fakeHome(t)

	// (a) Legacy DB present, target absent: imported, byte-identical,
	// source intact, rollback instructions in the note.
	legacyDir := filepath.Join(home, ".gseer")
	legacy := newEmptyPersonalDB(t, legacyDir, "gseer.db")
	legacyHash := fileHash(t, legacy)
	target := defaultPersonalDBPath()

	imported, note, err := importLegacyPersonalDB(target)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	if !imported {
		t.Fatal("the legacy database must be imported on first provisioning")
	}
	if got := fileHash(t, target); got != legacyHash {
		t.Errorf("imported copy is not byte-identical to the legacy database")
	}
	if got := fileHash(t, legacy); got != legacyHash {
		t.Errorf("the legacy source was modified — it must never be touched")
	}
	if _, serr := os.Lstat(target + ".import-staging"); serr == nil {
		t.Errorf("the staged copy must be renamed away, not left behind")
	}
	if !strings.Contains(note, "roll back") || !strings.Contains(note, target) {
		t.Errorf("the note must spell out the rollback and the new path, got: %s", note)
	}

	// (b) Target already present: refuse to overwrite (idempotent no-op).
	if imported, _, err := importLegacyPersonalDB(target); err != nil || imported {
		t.Errorf("a second import must be a no-op (imported=%v err=%v)", imported, err)
	}

	// (c) No legacy DB anywhere: clean no-op, nothing created.
	empty := fakeHome(t)
	if imported, _, err := importLegacyPersonalDB(filepath.Join(empty, ".local", "state", "gseer", "gseer.db")); err != nil || imported {
		t.Errorf("no legacy DB must be a no-op (imported=%v err=%v)", imported, err)
	}
	if _, serr := os.Lstat(filepath.Join(empty, ".local", "state", "gseer")); serr == nil {
		t.Errorf("a no-op import must not create the state directory")
	}

	// (d) Legacy path is a directory: refuse with the original untouched.
	home = fakeHome(t)
	target = defaultPersonalDBPath() // re-resolve for the fresh home
	dir := filepath.Join(home, ".gseer", "gseer.db")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := importLegacyPersonalDB(target); err == nil {
		t.Errorf("importing a directory source must fail")
	}

	// (e) GSEER_HOME install: source == target — structurally nothing to
	// migrate.
	fakeHome(t)
	gh := t.TempDir()
	t.Setenv("GSEER_HOME", gh)
	if imported, _, err := importLegacyPersonalDB(defaultPersonalDBPath()); err != nil || imported {
		t.Errorf("a GSEER_HOME install must skip the import (imported=%v err=%v)", imported, err)
	}
}

// TestImportLegacyRollsBackOnFailure pins the inline rollback: when the
// staged copy cannot be created (read-only target directory), the call
// fails, the legacy source survives, and NO staging file is left behind.
func TestImportLegacyRollsBackOnFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission-based failure injection requires a non-root tester")
	}
	home := fakeHome(t)
	legacyDir := filepath.Join(home, ".gseer")
	legacy := newEmptyPersonalDB(t, legacyDir, "gseer.db")
	legacyHash := fileHash(t, legacy)

	targetDir := filepath.Join(home, ".local", "state", "gseer")
	if err := os.MkdirAll(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(targetDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(targetDir, 0o700) })

	target := filepath.Join(targetDir, "gseer.db")
	imported, _, err := importLegacyPersonalDB(target)
	if err == nil || imported {
		t.Fatalf("the import must fail on an unwritable target dir (imported=%v err=%v)", imported, err)
	}
	if _, serr := os.Lstat(target); serr == nil {
		t.Errorf("no target may exist after a failed import")
	}
	if _, serr := os.Lstat(target + ".import-staging"); serr == nil {
		t.Errorf("the inline rollback must remove the staged copy")
	}
	if got := fileHash(t, legacy); got != legacyHash {
		t.Errorf("the legacy source must survive a failed import byte-identical")
	}
}

// TestSetupPersonalMigratesLegacyDefault is the end-to-end contract:
// `gseer setup --personal` (and the zero-configuration first run share
// this exact code path) provisions at the NEW persistent default and,
// when the operator has a pre-Rev16 database, imports it with the
// rollback note — the legacy file and any explicit DSN are untouched.
func TestSetupPersonalMigratesLegacyDefault(t *testing.T) {
	home := fakeHome(t)
	legacy := newEmptyPersonalDB(t, filepath.Join(home, ".gseer"), "gseer.db")
	legacyHash := fileHash(t, legacy)

	cmd := &cobra.Command{Use: "setup"}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	if err := runSetupPersonal(cmd, "", false); err != nil {
		t.Fatalf("setup --personal: %v\noutput:\n%s", err, buf.String())
	}

	out := buf.String()
	target := defaultPersonalDBPath()
	if _, serr := os.Stat(target); serr != nil {
		t.Errorf("the database must be provisioned at the new default %s: %v", target, serr)
	}
	if got := fileHash(t, target); got != legacyHash {
		t.Errorf("the provisioned database must be the imported legacy content")
	}
	if got := fileHash(t, legacy); got != legacyHash {
		t.Errorf("the legacy database must survive the migration byte-identical")
	}
	if !strings.Contains(out, "imported your existing personal database") {
		t.Errorf("the output must report the legacy import, got:\n%s", out)
	}
	if !strings.Contains(out, "roll back") {
		t.Errorf("the output must carry the rollback instructions, got:\n%s", out)
	}

	// The written config points at the NEW location (explicit DSN path —
	// what every following command resolves).
	cfgBytes, rerr := os.ReadFile(filepath.Join(home, ".gseer", "config.yaml"))
	if rerr != nil {
		t.Fatalf("read config: %v", rerr)
	}
	if !strings.Contains(string(cfgBytes), target) {
		t.Errorf("the config DSN must point at the new location %s, got:\n%s", target, cfgBytes)
	}
}

// TestSetupPersonalRespectsExplicitDBPath pins that an explicit --db-path
// is honored verbatim (no import, no relocation — only the /tmp warning
// may appear, and only for volatile paths).
func TestSetupPersonalRespectsExplicitDBPath(t *testing.T) {
	home := fakeHome(t)
	legacy := newEmptyPersonalDB(t, filepath.Join(home, ".gseer"), "gseer.db")
	legacyHash := fileHash(t, legacy)

	explicit := filepath.Join(t.TempDir(), "custom-personal.db")
	cmd := &cobra.Command{Use: "setup"}
	buf := &bytes.Buffer{}
	cmd.SetOut(buf)
	if err := runSetupPersonal(cmd, explicit, false); err != nil {
		t.Fatalf("setup --personal --db-path: %v", err)
	}
	if _, serr := os.Stat(explicit); serr != nil {
		t.Errorf("the explicit database path must be provisioned verbatim: %v", serr)
	}
	if _, serr := os.Stat(defaultPersonalDBPath()); serr == nil {
		t.Errorf("an explicit --db-path must not create the default location")
	}
	if got := fileHash(t, legacy); got != legacyHash {
		t.Errorf("an explicit --db-path must not touch the legacy default")
	}
	if strings.Contains(buf.String(), "imported your existing personal database") {
		t.Errorf("an explicit --db-path must not trigger the legacy import")
	}
}
