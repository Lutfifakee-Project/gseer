// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

// Package config implements YAML configuration loading, environment-
// variable overlay, CLI flag precedence, strict schema validation, and
// actionable E_* errors for the GSEER v0.0.1 binary (SPEC-03 §5, §7).
//
// Precedence (highest wins): CLI flags > environment variables > YAML
// config file > owner-approved defaults (PD-1…PD-9).
//
// Load order (corrected per owner M2 review):
// YAML → env → flags → defaults (profile-dependent) → validate.
// Defaults are applied AFTER env+flags so profile-dependent defaults
// (database components) use the FINAL resolved profile.
//
// # Profiles (SPEC-03 §5, as amended by the v0.3.2 CLI-only decision)
//
// Two profiles are supported:
//
//   - personal     — the full engine against ONE embedded SQLite file
//     (the Local Index).  Zero-configuration default; provisioned by
//     `gseer setup`.
//   - self-hosted  — the same CLI engine headless over PostgreSQL
//     (operator-provisioned).  Migrations run on `setup --self-hosted`.
//
// Neither profile ships data and neither serves a network API: GSEER
// is a CLI-only product (the client profile, server.* settings, and
// the shared-index channel were removed with the API/dashboard
// surfaces).
//
// # Strict schema (AC-7.x)
//
// Unknown YAML keys are rejected with E_CONFIG_UNKNOWN_KEY.  Any
// `policy.active.*` key is rejected with E_CONFIG_POLICY_ACTIVE_REJECTED
// and a pointer to v0.0.2 — active collection is not part of v0.0.1 and
// the config layer enforces this at load time, not just structurally.
//
// `InsecureSkipVerify` and similar unsafe keys are rejected with
// E_CONFIG_INSECURE for any control-plane endpoint.
//
// # Credential handling (honest terminology)
//
// The remaining credential surfaces:
//
//  1. Database password (DatabaseConfig.Password) — needed for the
//     PostgreSQL connection DSN.  Passed to pgx (M3) as part of the
//     connection string.  The password is percent-encoded in the DSN
//     via net/url (Finding 4), but the plaintext is required for the
//     connection.  This field must NEVER appear in logs or diagnostic
//     output.
//
//  2. The personal profile has NO database credential at all: the
//     single SQLite file's 0600 filesystem permission IS the credential
//     boundary (database.runtime_dsn is rejected in personal mode).
//
// # Logging restrictions (M3)
//
// Until a SEC-6 slog redaction handler lands, the following are
// PENDING and must be enforced by discipline in M3:
//
//   - DatabaseConfig.Password must not appear in any log line, error
//     message, or doctor output.
//   - The effective DSN (which embeds the password) must not be logged
//     directly; M3 must log a redacted form (host:port/db, no userinfo).
//
// The `yaml:"password,omitempty"` struct tag only controls YAML
// marshaling (omit when empty); it does NOT provide logging redaction.
package config
