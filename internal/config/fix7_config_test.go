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

// fix7_config_test.go — v0.3.2 pins for the audited setup failures
// (STAGE 2 report §8) and the new index.* config section:
//
//   1. validateSelfHosted refuses a non-postgres:// DSN (the mirror of
//      the personal guard — the exact bug that made
//      `gseer setup --self-hosted` hand a SQLite file path to pgx);
//   2. the client E_CONFIG_REQUIRED hint is no longer circular (it
//      names an actionable command);
//   3. index.manifest_url transport validation (https; http loopback
//      only);
//   4. index.* keys are personal-only (client/self-hosted conflict).

import (
	"strings"
	"testing"
)

func TestValidateSelfHostedRejectsNonPostgresDSN(t *testing.T) {
	c := &Config{
		Profile:  ProfileSelfHosted,
		Database: DatabaseConfig{DSN: "/home/operator/.gseer/gseer.db"},
	}
	err := Validate(c)
	if err == nil {
		t.Fatal("SQLite file path accepted as a self-hosted DSN — the audited v0.3.1 bug must stay fixed")
	}
	if err.Code != CodeConfigInvalidValue {
		t.Fatalf("code = %s, want %s", err.Code, CodeConfigInvalidValue)
	}
	// The DSN value is never echoed (it may embed credentials).
	if strings.Contains(err.Error(), "/home/operator") {
		t.Fatalf("error echoes the DSN: %s", err.Error())
	}

	// postgres:// and postgresql:// pass.
	for _, dsn := range []string{
		"postgres://gseer:pw@127.0.0.1:5432/gseer?sslmode=disable",
		"postgresql://gseer@127.0.0.1:5432/gseer?sslmode=disable",
	} {
		c2 := &Config{Profile: ProfileSelfHosted, Database: DatabaseConfig{DSN: dsn}}
		if err := Validate(c2); err != nil {
			t.Fatalf("valid PG DSN rejected: %v", err)
		}
	}
}

func TestClientEndpointHintIsActionable(t *testing.T) {
	c := &Config{Profile: ProfileClient}
	err := Validate(c)
	if err == nil || err.Code != CodeConfigRequired {
		t.Fatalf("want E_CONFIG_REQUIRED, got %v", err)
	}
	next := err.Next
	if !strings.Contains(next, "--server") {
		t.Fatalf("client hint is still circular (no actionable --server command): %q", next)
	}
	if strings.Contains(next, "or: gseer setup --self-hosted") {
		t.Fatalf("client hint still steers into the self-hosted trap: %q", next)
	}
}

func TestIndexManifestURLValidation(t *testing.T) {
	ok := []string{
		"https://github.com/Lutfifakee-Project/gseer/releases/download/shared-index/gseer-index-manifest.json",
		"http://127.0.0.1:8080/manifest.json",
		"http://localhost:9090/manifest.json",
		"http://[::1]:8080/manifest.json",
	}
	for _, u := range ok {
		c := &Config{Profile: ProfilePersonal, Database: DatabaseConfig{DSN: "/tmp/x.db"}, Index: IndexConfig{ManifestURL: u}}
		if err := Validate(c); err != nil {
			t.Fatalf("valid index URL %q rejected: %v", u, err)
		}
	}
	bad := []string{
		"http://example.com/manifest.json", // plaintext to a non-local host
		"ftp://example.com/manifest.json",
		"not a url",
		"/local/path.json",
	}
	for _, u := range bad {
		c := &Config{Profile: ProfilePersonal, Database: DatabaseConfig{DSN: "/tmp/x.db"}, Index: IndexConfig{ManifestURL: u}}
		if err := Validate(c); err == nil || err.Code != CodeConfigInvalidValue {
			t.Fatalf("invalid index URL %q accepted: %v", u, err)
		}
	}
}

func TestIndexKeysArePersonalOnly(t *testing.T) {
	client := &Config{Profile: ProfileClient, Client: ClientConfig{Endpoint: "https://x"},
		Index: IndexConfig{ManifestURL: "https://x/m.json"}}
	if err := Validate(client); err == nil || err.Code != CodeConfigProfileConflict {
		t.Fatalf("client profile accepted index.*: %v", err)
	}
	selfHosted := &Config{Profile: ProfileSelfHosted,
		Database: DatabaseConfig{DSN: "postgres://gseer@127.0.0.1:5432/gseer?sslmode=disable"},
		Index:    IndexConfig{ManifestURL: "https://x/m.json"}}
	if err := Validate(selfHosted); err == nil || err.Code != CodeConfigProfileConflict {
		t.Fatalf("self-hosted profile accepted index.*: %v", err)
	}
	personal := &Config{Profile: ProfilePersonal, Database: DatabaseConfig{DSN: "/tmp/x.db"},
		Index: IndexConfig{ManifestURL: "https://x/m.json"}}
	if err := Validate(personal); err != nil {
		t.Fatalf("personal profile rejected index.*: %v", err)
	}
}

func TestEnvIndexManifestURLMapping(t *testing.T) {
	t.Setenv("GSEER_INDEX_MANIFEST_URL", "https://idx.example.com/manifest.json")
	t.Setenv("GSEER_DB_DSN", "/tmp/gseer-env-test.db")
	cfg, lerr := Load(Flags{Profile: string(ProfilePersonal)})
	if lerr != nil {
		t.Fatalf("load: %v", lerr)
	}
	if cfg.Index.ManifestURL != "https://idx.example.com/manifest.json" {
		t.Fatalf("GSEER_INDEX_MANIFEST_URL did not map: %q", cfg.Index.ManifestURL)
	}
}
