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
//   - resolveConfigWritePath mirrors the loader's own resolution
//     (--config flag > GSEER_CONFIG > platform default, loader.go) so
//     setup updates the SAME file every following command loads;
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

// resolveConfigWritePath returns the config file setup may update:
// the same resolution order the loader uses, so the file written here
// is the file `gseer status`/`gseer doctor`/engine commands read.
func resolveConfigWritePath() string {
	if flags.configPath != "" {
		return flags.configPath
	}
	if v, ok := os.LookupEnv("GSEER_CONFIG"); ok && v != "" {
		return v
	}
	return defaultConfigPath()
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
	raw, rerr := os.ReadFile(path)
	if rerr != nil {
		return fmt.Errorf("cannot read the config %s: %w", path, rerr)
	}
	mode := os.FileMode(0o600)
	if st, serr := os.Stat(path); serr == nil {
		mode = st.Mode().Perm()
	}
	lines := strings.Split(string(raw), "\n")

	foundProfile := false
	foundDatabase := false
	foundDSN := false
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
				foundDSN = true
				continue
			}
		}
		if topLevel && !comment {
			if strings.HasPrefix(trimmed, "database:") {
				if rest := strings.TrimSpace(strings.TrimPrefix(trimmed, "database:")); rest != "" {
					return fmt.Errorf("the config %s uses a flow-style database mapping; add "+
						"`dsn: %s` under database: manually — setup refuses to edit it programmatically",
						path, dbPath)
				}
				inDatabase = true
				foundDatabase = true
				continue
			}
			if strings.HasPrefix(trimmed, "profile:") {
				lines[i] = "profile: personal"
				foundProfile = true
				continue
			}
		}
	}

	if foundDatabase && !foundDSN {
		for i, ln := range lines {
			if strings.TrimSpace(ln) == "database:" {
				head := append([]string{}, lines[:i+1]...)
				tail := append([]string{}, lines[i+1:]...)
				lines = append(head, append([]string{"  dsn: " + yamlQuote(dbPath)}, tail...)...)
				break
			}
		}
	}
	if !foundDatabase {
		lines = append(lines, "", "database:", "  dsn: "+yamlQuote(dbPath))
	}
	if !foundProfile {
		lines = append([]string{"profile: personal"}, lines...)
	}

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), mode); err != nil {
		return fmt.Errorf("cannot write the config %s: %w", path, err)
	}
	return nil
}
