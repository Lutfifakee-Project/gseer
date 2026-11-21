// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package config

// fix7_config_test.go — v0.3.2 pins for the audited setup failures
// (STAGE 2 report §8):
//
//   1. validateSelfHosted refuses a non-postgres:// DSN (the mirror of
//      the personal guard — the exact bug that made
//      `gseer setup --self-hosted` hand a SQLite file path to pgx).
//
// The client-profile hint, index.manifest_url transport validation, and
// index.* profile-conflict pins were removed with the client profile
// and the shared-index channel (v0.3.2 CLI-only architecture).

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

// TestDefaultProfileIsPersonal pins the CLI-only default: with no
// profile configured anywhere, the zero-configuration default is the
// personal (Local Index) profile.
func TestDefaultProfileIsPersonal(t *testing.T) {
	c := &Config{}
	applyDefaults(c)
	if c.Profile != ProfilePersonal {
		t.Fatalf("default profile = %q, want %q (the zero-configuration product default)", c.Profile, ProfilePersonal)
	}
}
