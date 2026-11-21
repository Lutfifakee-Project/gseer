// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package migrations

// artifacts_lf_test.go — platform-determinism regression for the
// artifact-hash pin (AC-117).  Detects the original Windows failure
// mode directly: if .gitattributes ever stops forcing LF for *.sql, a
// Windows checkout with core.autocrlf=true embeds CRLF bytes via
// go:embed, and TestPinnedMigrationArtifactsMatchRegister /
// TestPinnedDeploymentArtifactsMatchRegister drift from the register.
//
// This test fails BEFORE the hash comparison by asserting no CR (\r)
// byte is present in the embedded content — so the failure message
// points unambiguously at the line-ending normalization rather than at
// an opaque hash mismatch.  It runs on every platform (no build tag):
// Linux passes trivially (LF checkout); Windows passes only while
// .gitattributes enforces eol=lf.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/deploy"
)

func TestPinnedArtifactsAreLFOnAllPlatforms(t *testing.T) {
	for name := range pinnedArtifacts {
		raw, err := FS.ReadFile(name)
		if err != nil {
			t.Fatalf("pinned artifact %s is not embedded: %v", name, err)
		}
		if bytes.IndexByte(raw, '\r') >= 0 {
			t.Errorf("pinned artifact %s contains CR (\\r) bytes — .gitattributes *.sql eol=lf is not enforced on this checkout; "+
				"a Windows core.autocrlf=true checkout would embed CRLF and drift the register hash", name)
		}
	}
	for name, sql := range map[string]string{
		"gseer_v0672_bootstrap_roles.sql":           deploy.BootstrapRolesSQL,
		"gseer_v0672_runtime_grants_setup.sql":      deploy.RuntimeGrantsSQL,
		"gseer_v0672_effective_privilege_audit.sql": deploy.EffectivePrivilegeAuditSQL,
	} {
		if strings.IndexByte(sql, '\r') >= 0 {
			t.Errorf("deploy artifact %s contains CR (\\r) bytes — .gitattributes *.sql eol=lf is not enforced on this checkout", name)
		}
	}
}
