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

package config

import (
	"path/filepath"
	"testing"
)

// profile_defaults_test.go — tests for the owner's M2 review Finding 1:
// profile-dependent defaults must be applied based on the FINAL resolved
// profile (after env + flags), not the YAML/env profile.
//
// The corrected Load order (loader.go) applies defaults AFTER env + flags,
// so the final resolved profile drives the defaults.  v0.3.2 CLI-only
// architecture: the client-profile scenarios are gone — the two profiles
// are personal (SQLite Local Index) and self-hosted (PostgreSQL).

// helper: load a fixture with a clean env and the given flags.
func loadForProfileTest(t *testing.T, fixture string, flags Flags) (*Config, *Error) {
	t.Helper()
	// Clear profile-related env vars so they don't interfere.
	for _, k := range []string{
		"GSEER_PROFILE", "GSEER_DB_HOST",
		"GSEER_DB_PORT", "GSEER_DB_USER", "GSEER_DB_PASSWORD", "GSEER_DB_NAME",
		"GSEER_DB_DSN", "GSEER_DB_SSLMODE", "GSEER_CONFIG",
	} {
		t.Setenv(k, "")
	}
	path := ""
	if fixture != "" {
		path = filepath.Join("testdata", fixture)
	}
	flags.ConfigPath = path
	return Load(flags)
}

// Scenario 1: YAML self-hosted (no DB fields) → CLI personal.
// The final profile is personal; PostgreSQL DB defaults must NOT be
// applied (personal stores a FILE path, not components).
func TestProfileDefaults_Scenario1_YAMLSelfHostedToCLIPersonal(t *testing.T) {
	// personal-minimal.yaml carries the database FILE path, so only the
	// profile-dependent DEFAULTS are under test.
	c, e := loadForProfileTest(t, "personal-minimal.yaml", Flags{Profile: "personal"})
	if e != nil {
		t.Fatalf("expected success, got %v", e)
	}
	if c.Profile != ProfilePersonal {
		t.Errorf("Profile: want personal, got %q", c.Profile)
	}
	if c.Database.Host != "" {
		t.Errorf("Database.Host should be empty (personal profile, no DB defaults); got %q", c.Database.Host)
	}
	if c.Database.Port != 0 {
		t.Errorf("Database.Port should be 0 (personal profile); got %d", c.Database.Port)
	}
}

// Scenario 2: YAML personal → CLI self-hosted.
// The final profile is self-hosted; DB defaults MUST be applied.
func TestProfileDefaults_Scenario2_YAMLPersonalToCLISelfHosted(t *testing.T) {
	c, e := loadForProfileTest(t, "", Flags{Profile: "self-hosted"})
	if e != nil {
		t.Fatalf("expected success, got %v", e)
	}
	if c.Profile != ProfileSelfHosted {
		t.Errorf("Profile: want self-hosted, got %q", c.Profile)
	}
	if c.Database.Host != DefaultDBHost {
		t.Errorf("Database.Host: want %q (default applied for self-hosted), got %q", DefaultDBHost, c.Database.Host)
	}
	if c.Database.Port != DefaultDBPort {
		t.Errorf("Database.Port: want %d, got %d", DefaultDBPort, c.Database.Port)
	}
}

// Scenario 3: Environment self-hosted → CLI personal.
// Env sets GSEER_PROFILE=self-hosted; CLI sets --profile=personal.
// Final profile is personal; DB defaults must NOT be applied.
func TestProfileDefaults_Scenario3_EnvSelfHostedToCLIPersonal(t *testing.T) {
	for _, k := range []string{
		"GSEER_PROFILE", "GSEER_DB_HOST",
		"GSEER_DB_PORT", "GSEER_DB_USER", "GSEER_DB_PASSWORD", "GSEER_DB_NAME",
		"GSEER_DB_DSN", "GSEER_DB_SSLMODE", "GSEER_CONFIG",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("GSEER_PROFILE", "self-hosted")
	// personal requires a database FILE path; provide it so only the
	// profile precedence is under test.
	t.Setenv("GSEER_DB_DSN", "/tmp/profile-scenario3/gseer.db")
	c, e := Load(Flags{Profile: "personal"})
	if e != nil {
		t.Fatalf("expected success, got %v", e)
	}
	if c.Profile != ProfilePersonal {
		t.Errorf("Profile: want personal (CLI overrides env), got %q", c.Profile)
	}
	if c.Database.Host != "" {
		t.Errorf("Database.Host should be empty (personal profile); got %q", c.Database.Host)
	}
}

// Scenario 4: Environment personal → CLI self-hosted.
// Env sets GSEER_PROFILE=personal; CLI sets --profile=self-hosted.
// Final profile is self-hosted; DB defaults MUST be applied.
func TestProfileDefaults_Scenario4_EnvPersonalToCLISelfHosted(t *testing.T) {
	for _, k := range []string{
		"GSEER_PROFILE", "GSEER_DB_HOST",
		"GSEER_DB_PORT", "GSEER_DB_USER", "GSEER_DB_PASSWORD", "GSEER_DB_NAME",
		"GSEER_DB_DSN", "GSEER_DB_SSLMODE", "GSEER_CONFIG",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("GSEER_PROFILE", "personal")
	c, e := Load(Flags{Profile: "self-hosted"})
	if e != nil {
		t.Fatalf("expected success, got %v", e)
	}
	if c.Profile != ProfileSelfHosted {
		t.Errorf("Profile: want self-hosted (CLI overrides env), got %q", c.Profile)
	}
	if c.Database.Host != DefaultDBHost {
		t.Errorf("Database.Host: want %q (default for self-hosted), got %q", DefaultDBHost, c.Database.Host)
	}
}

// Scenario 5: No YAML + profile selected by CLI.
// No config file, no env profile; CLI sets --profile=self-hosted.
// Final profile is self-hosted; DB defaults MUST be applied.
func TestProfileDefaults_Scenario5_NoYAMLProfileByCLI(t *testing.T) {
	c, e := loadForProfileTest(t, "", Flags{Profile: "self-hosted"})
	if e != nil {
		t.Fatalf("expected success, got %v", e)
	}
	if c.Profile != ProfileSelfHosted {
		t.Errorf("Profile: want self-hosted, got %q", c.Profile)
	}
	if c.Source != "env-only" {
		t.Errorf("Source: want 'env-only', got %q", c.Source)
	}
	if c.Database.Host != DefaultDBHost {
		t.Errorf("Database.Host: want %q, got %q", DefaultDBHost, c.Database.Host)
	}
}
