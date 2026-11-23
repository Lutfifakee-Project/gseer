// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"fmt"
	"os"
	"strings"
)

// personal_config_write.go — QS-6 R3: the operator's config file is
// never replaced wholesale.
//
// BLOCKER (owner acceptance, QS-6 setup isolation): the old tail of
// runSetupPersonal called writePersonalConfig unconditionally — a
// hand-rolled minimal YAML that DROPPED every key it did not write and
// stamped the resolved default path over an explicit database.dsn.
//
// This file adds the surgical alternative:
//
//   - upsertPersonalConfig edits an existing, loadable config line by
//     line, touching ONLY the `profile:` scalar and the `database:` /
//     `dsn:` scalar — every other key, comment, quoting style and
//     ordering survives byte-for-byte.
//
// The edit is deliberately line-based and NOT a yaml.Marshal
// round-trip: a marshal reorders keys, drops comments and rewrites
// quoting — precisely the data loss R3 forbids.  For the loader's own
// schema (scalar profile, block-or-scalar database.dsn) the surgical
// edit is exact; flow-style `database: {…}` mappings are refused with
// a manual instruction instead of being guessed at.

// resolveConfigWritePath and the QS-6/R3 wiring above it are gone: the
// setup flow resolves the operator's config path through the loader
// directly, so the file edited here is still the file every following
// command loads.

// personalConfigScan records what one scan pass learned about the
// existing config file.
type personalConfigScan struct {
	foundProfile  bool
	foundDatabase bool
	foundDSN      bool
}

// upsertPersonalConfig updates an EXISTING config file in place with
// `profile: personal` and `database: dsn: <dbPath>` while preserving
// every other key, comment and line.  Behavior:
//
//   - an existing top-level `profile:` scalar is replaced in place;
//     a missing one is prepended as the first line;
//   - an existing top-level `database:` block: its `dsn:` scalar is
//     replaced in place (indentation preserved); a block without a
//     dsn scalar gets the dsn inserted right after the header;
//   - no `database:` block → appended at the end;
//   - the file mode is preserved (writePersonalConfig's 0600 policy
//     governs the fresh-file path, not this one).
func upsertPersonalConfig(path string, dbPath string) error {
	// #nosec G304 -- the operator-chosen config path (--config flag >
	// GSEER_CONFIG > platform default) is the feature itself (QS-6/R3):
	// a local, single-user dataflow with no remote or cross-user input.
	// Restricting the path would change documented CLI behavior.
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		return fmt.Errorf("cannot read the config %s: %w", path, rerr)
	}
	mode := os.FileMode(0o600)
	if st, serr := os.Stat(path); serr == nil {
		mode = st.Mode().Perm()
	}
	lines := strings.Split(string(raw), "\n")

	scan, err := scanPersonalConfigLines(lines, path, dbPath)
	if err != nil {
		return err
	}
	if scan.foundDatabase && !scan.foundDSN {
		lines = insertMissingDSN(lines, dbPath)
	}
	lines = applyMissingBlocks(lines, scan, dbPath)

	// #nosec G703 -- the same operator-chosen config path as above; no
	// remote or cross-user input reaches this write (QS-6/R3 design).
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), mode); err != nil {
		return fmt.Errorf("cannot write the config %s: %w", path, err)
	}
	return nil
}

// scanPersonalConfigLines rewrites the profile/dsn lines it recognizes
// IN PLACE (index-addressed, so indentation survives) and reports what
// the file already contains.  A flow-style `database: {…}` mapping is
// refused instead of guessed at.  The line grammar is the loader's own
// schema: scalar profile, block-or-scalar database.dsn.
func scanPersonalConfigLines(lines []string, path string, dbPath string) (personalConfigScan, error) {
	var scan personalConfigScan
	inDatabase := false

	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		comment := strings.HasPrefix(trimmed, "#")
		topLevel := ln != "" && ln[0] != ' ' && ln[0] != '\t'

		if inDatabase {
			if topLevel && trimmed != "" && !comment {
				inDatabase = false // a new top-level key ends the block
			} else if !comment && strings.HasPrefix(trimmed, "dsn:") {
				indent := ln[:len(ln)-len(strings.TrimLeft(ln, " \t"))]
				lines[i] = indent + "dsn: " + yamlQuote(dbPath)
				scan.foundDSN = true
				continue
			}
		}
		if topLevel && !comment {
			if strings.HasPrefix(trimmed, "database:") {
				if rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "database:")); rest != "" {
					return scan, fmt.Errorf("the config %s uses a flow-style database mapping; add "+
						"`dsn: %s` under database: manually — setup refuses to edit it programmatically",
						path, dbPath)
				}
				inDatabase = true
				scan.foundDatabase = true
				continue
			}
			if strings.HasPrefix(trimmed, "profile:") {
				lines[i] = "profile: personal"
				scan.foundProfile = true
				continue
			}
		}
	}
	return scan, nil
}

// insertMissingDSN inserts `  dsn: <dbPath>` right after the first
// exact `database:` header line (caller: the scan saw a block whose dsn
// scalar is absent).  Rebuilt via fresh appends so no aliasing surprise
// can alias the input slice (gocritic appendAssign).
func insertMissingDSN(lines []string, dbPath string) []string {
	for i, ln := range lines {
		if strings.TrimSpace(ln) != "database:" {
			continue
		}
		rebuilt := make([]string, 0, len(lines)+1)
		rebuilt = append(rebuilt, lines[:i+1]...)
		rebuilt = append(rebuilt, "  dsn: "+yamlQuote(dbPath))
		rebuilt = append(rebuilt, lines[i+1:]...)
		return rebuilt
	}
	return lines
}

// applyMissingBlocks appends a fresh `database:` block when the file
// has none and prepends `profile: personal` when no profile scalar
// exists — in that order, matching the historical single-pass order.
func applyMissingBlocks(lines []string, scan personalConfigScan, dbPath string) []string {
	if !scan.foundDatabase {
		lines = append(lines, "", "database:", "  dsn: "+yamlQuote(dbPath))
	}
	if !scan.foundProfile {
		lines = append([]string{"profile: personal"}, lines...)
	}
	return lines
}
