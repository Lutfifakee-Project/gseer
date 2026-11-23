// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// helper: load a testdata fixture by name, with no flags and a clean env.
func loadFixture(t *testing.T, name string) (*Config, *Error) {
	t.Helper()
	path := filepath.Join("testdata", name)
	// Clear all GSEER_* env vars so they don't leak into the test.
	for _, k := range []string{
		"GSEER_PROFILE", "GSEER_CLIENT_ENDPOINT", "GSEER_LISTEN", "GSEER_TOKEN",
		"GSEER_DB_DSN", "GSEER_DB_HOST", "GSEER_DB_PORT", "GSEER_DB_USER",
		"GSEER_DB_PASSWORD", "GSEER_DB_NAME", "GSEER_DB_SSLMODE",
		"GSEER_LOG_LEVEL", "GSEER_LOG_FORMAT", "GSEER_POLICY_EVALUATION_FIXTURES",
		"GSEER_CONFIG",
	} {
		t.Setenv(k, "")
	}
	return Load(Flags{ConfigPath: path})
}

// TestLoadValidSelfHosted verifies the happy path: a valid self-hosted
// config loads and the owner-approved defaults are applied.  (v0.3.2
// CLI-only architecture: server.*/token hashing was removed with the
// API-server surface — the config schema no longer carries them.)
func TestLoadValidSelfHosted(t *testing.T) {
	c, e := loadFixture(t, "valid-selfhosted.yaml")
	if e != nil {
		t.Fatalf("expected success, got error: %v", e)
	}
	if c.Profile != ProfileSelfHosted {
		t.Errorf("Profile: want %q, got %q", ProfileSelfHosted, c.Profile)
	}
	if c.Database.EffectiveDSN() == "" {
		t.Error("EffectiveDSN must resolve from the database components")
	}
	if c.Database.Port != 5432 {
		t.Errorf("Database.Port: want 5432, got %d", c.Database.Port)
	}
	// Defaults populated.
	if c.Defaults.SearchMode != DefaultSearchMode {
		t.Errorf("Defaults.SearchMode: want %q, got %q", DefaultSearchMode, c.Defaults.SearchMode)
	}
	if c.Defaults.PostgresMajor != DefaultPostgresMajor {
		t.Errorf("Defaults.PostgresMajor: want %d, got %d", DefaultPostgresMajor, c.Defaults.PostgresMajor)
	}
}

// TestLoadPolicyActiveRejected verifies that any policy.active.*
// key is rejected with E_CONFIG_POLICY_ACTIVE_REJECTED.
func TestLoadPolicyActiveRejected(t *testing.T) {
	_, e := loadFixture(t, "invalid-policy-active.yaml")
	if e == nil {
		t.Fatal("expected E_CONFIG_POLICY_ACTIVE_REJECTED, got nil")
	}
	if e.Code != CodeConfigPolicyActiveRejected {
		t.Errorf("Code: want %q, got %q", CodeConfigPolicyActiveRejected, e.Code)
	}
	// The error must point the operator at the rejected-key policy.
	if !contains(e.Error(), ".env.example") {
		t.Errorf("error must point at .env.example (rejected-key policy); got: %v", e)
	}
}

// TestLoadUnknownKeyRejected verifies strict schema: unknown keys
// are rejected with E_CONFIG_UNKNOWN_KEY.
func TestLoadUnknownKeyRejected(t *testing.T) {
	_, e := loadFixture(t, "invalid-unknown-key.yaml")
	if e == nil {
		t.Fatal("expected E_CONFIG_UNKNOWN_KEY, got nil")
	}
	if e.Code != CodeConfigUnknownKey {
		t.Errorf("Code: want %q, got %q", CodeConfigUnknownKey, e.Code)
	}
}

// TestLoadInsecureRejected verifies unsafe keys (InsecureSkipVerify)
// are rejected with E_CONFIG_INSECURE.
func TestLoadInsecureRejected(t *testing.T) {
	_, e := loadFixture(t, "invalid-insecure.yaml")
	if e == nil {
		t.Fatal("expected E_CONFIG_INSECURE, got nil")
	}
	if e.Code != CodeConfigInsecure {
		t.Errorf("Code: want %q, got %q", CodeConfigInsecure, e.Code)
	}
}

// TestLoadMalformed verifies YAML parse errors produce E_CONFIG_PARSE.
func TestLoadMalformed(t *testing.T) {
	_, e := loadFixture(t, "invalid-malformed.yaml")
	if e == nil {
		t.Fatal("expected E_CONFIG_PARSE, got nil")
	}
	if e.Code != CodeConfigParse {
		t.Errorf("Code: want %q, got %q", CodeConfigParse, e.Code)
	}
}

// TestLoadFileNotFound verifies a missing --config path errors with
// E_CONFIG_FILE_NOT_FOUND.
func TestLoadFileNotFound(t *testing.T) {
	for _, k := range []string{"GSEER_CONFIG", "GSEER_PROFILE", "GSEER_CLIENT_ENDPOINT"} {
		t.Setenv(k, "")
	}
	_, e := Load(Flags{ConfigPath: "/nonexistent/path/config.yaml"})
	if e == nil {
		t.Fatal("expected E_CONFIG_FILE_NOT_FOUND, got nil")
	}
	if e.Code != CodeConfigFileNotFound {
		t.Errorf("Code: want %q, got %q", CodeConfigFileNotFound, e.Code)
	}
}

// TestLoadEnvOnly verifies that with no config file, env vars alone
// produce a valid personal config (Source = "env-only") — the
// zero-configuration default profile is personal.
func TestLoadEnvOnly(t *testing.T) {
	for _, k := range []string{"GSEER_CONFIG"} {
		t.Setenv(k, "")
	}
	t.Setenv("GSEER_PROFILE", "personal")
	t.Setenv("GSEER_DB_DSN", "/tmp/env-only-personal/gseer.db")
	c, e := Load(Flags{})
	if e != nil {
		t.Fatalf("env-only load failed: %v", e)
	}
	if c.Source != "env-only" {
		t.Errorf("Source: want 'env-only', got %q", c.Source)
	}
	if c.Profile != ProfilePersonal {
		t.Errorf("Profile: want %q, got %q", ProfilePersonal, c.Profile)
	}
	if c.Database.DSN != "/tmp/env-only-personal/gseer.db" {
		t.Errorf("DSN from env: want the env-provided file path, got %q", c.Database.DSN)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > 0 && indexOf(s, substr) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// TestMain removes the default config file location influence so tests
// don't pick up ~/.gseer/config.yaml from the dev environment.
func TestMain(m *testing.M) {
	// HOME points at the temp dir so defaultConfigPath() resolves the
	// same NON-EXISTENT location (never a real ~/.gseer/config.yaml).
	tmp, err := os.MkdirTemp("", "gseer-config-test-")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	_ = os.Setenv("HOME", tmp)
	os.Exit(m.Run())
}
