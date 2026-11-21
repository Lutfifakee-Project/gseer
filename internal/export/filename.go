// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package export

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// osStat is a test seam (the CLI tests do not touch the filesystem for
// the default-name branch).
var osStat = os.Stat

// filename.go — safe output-filename resolution (owner directive §4:
// "Safe output filenames").
//
// Rules:
//   - an explicit --out is cleaned; any ".." path segment is rejected
//     (no escaping the operator's chosen directory by surprise);
//   - control characters and leading "-" (option injection into shells)
//     are rejected;
//   - the default name is timestamped in the working directory;
//   - an existing non-empty file is refused unless the operator passes
//     --force — exports are never silently overwritten.

// ValidateOutPath checks an explicit --out value.
func ValidateOutPath(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("E_EXPORT_PATH: output path is empty")
	}
	// filepath.Clean on Windows converts / to \, so compare against the
	// OS-native form of the input: this accepts both separators everywhere
	// while still rejecting redundant separators, "." and ".." elements,
	// and trailing separators.
	native := filepath.FromSlash(name)
	if native != filepath.Clean(native) {
		return fmt.Errorf("E_EXPORT_PATH: path %q is not in clean form (use %q)", name, filepath.Clean(name))
	}
	// Check for ".." using both separators so mixed / \ paths are caught
	// on every OS (a /-separated path on Windows or a \-separated path on
	// Unix must still be rejected).
	for _, sep := range []string{string(filepath.Separator), "/"} {
		for _, part := range strings.Split(name, sep) {
			if part == ".." {
				return fmt.Errorf("E_EXPORT_PATH: path %q contains a \"..\" segment — choose a concrete directory", name)
			}
		}
	}
	if strings.ContainsAny(name, "\x00\n\r\t") {
		return fmt.Errorf("E_EXPORT_PATH: path %q contains control characters", name)
	}
	if strings.HasPrefix(name, "-") {
		return fmt.Errorf("E_EXPORT_PATH: output path %q starts with \"-\" (would look like a flag to shells)", name)
	}
	return nil
}

// ResolveOutPath returns the output path: the explicit value (validated)
// or a timestamped default with the format's extension.  existingOK
// suppresses the overwrite refusal (used by --force).
func ResolveOutPath(explicit, format string, force bool) (string, error) {
	name := explicit
	if name == "" {
		name = fmt.Sprintf("gseer-export-%s.%s", time.Now().UTC().Format("20060102-150405"), format)
	} else if err := ValidateOutPath(name); err != nil {
		return "", err
	}
	if !force {
		if st, err := osStat(name); err == nil && st.Size() > 0 {
			return "", fmt.Errorf("E_EXPORT_EXISTS: %s already exists and is not empty — pass --force to overwrite", name)
		}
	}
	return name, nil
}

// FormatExtension returns the canonical file extension for a format.
func FormatExtension(format string) string {
	switch format {
	case FormatNDJSON:
		return "ndjson"
	default:
		return format
	}
}
