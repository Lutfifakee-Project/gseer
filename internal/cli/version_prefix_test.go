// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// version_prefix_test.go — Rev16 cross-surface regression: the version
// string must be identical (one canonical "v"-prefixed form) on every
// display surface — banner, `gseer version`, status, doctor — no matter
// what shape the build pipeline injected.  The owner-acceptance finding
// was "vv0.3.1-snapshot" on the non-banner surfaces (raw echo of a
// v-prefixed GoReleaser snapshot injection) while the banner showed the
// de-duplicated form; normalization now happens at ONE choke point
// (version.Current), and these tests pin the surfaces together.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/version"
	"github.com/spf13/cobra"
)

func TestVersionPrefixConsistentAcrossSurfaces(t *testing.T) {
	orig := version.Version
	t.Cleanup(func() { version.Version = orig })
	version.Version = "vv0.3.1-snapshot" // the exact shape from the finding

	want := "v0.3.1-snapshot"

	// Banner: no doubled prefix, and identical to the canonical form.
	bv := bannerVersion()
	if strings.Contains(bv, "vv") {
		t.Errorf("banner renders a doubled version prefix: %q", bv)
	}
	if bv != "  "+want {
		t.Errorf("bannerVersion = %q, want %q", bv, "  "+want)
	}

	// `gseer version`: same canonical form.
	root := &cobra.Command{Use: "gseer"}
	registerVersionCmd(root)
	sub, _, err := root.Find([]string{"version"})
	if err != nil || sub == nil || sub.RunE == nil {
		t.Fatalf("the version subcommand must be registered with a RunE")
	}
	buf := &bytes.Buffer{}
	sub.SetOut(buf)
	if err := sub.RunE(sub, nil); err != nil {
		t.Fatalf("version command: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "gseer "+want) {
		t.Errorf("`gseer version` output must contain %q, got:\n%s", "gseer "+want, out)
	}
	if strings.Contains(out, "vv") {
		t.Errorf("`gseer version` renders a doubled prefix:\n%s", out)
	}

	// Status/doctor render version.Current().Version verbatim — assert the
	// choke point so any future surface that echoes the struct stays
	// consistent by construction.
	if got := version.Current().Version; got != want {
		t.Errorf("version.Current().Version = %q, want %q (status/doctor echo this)", got, want)
	}
}
