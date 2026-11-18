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
	"strings"
)

// profiles.go — profile validation per SPEC-03 §5.
//
// Each profile has a specific schema.  Mixing keys produces undefined
// behavior and is rejected (E_CONFIG_PROFILE_CONFLICT).  Missing
// required keys is rejected (E_CONFIG_REQUIRED).

// ValidateProfile checks that the config's fields are consistent with
// its declared profile.  Returns nil if consistent, or an *Error
// describing the first violation.
func ValidateProfile(c *Config) *Error {
	switch c.Profile {
	case ProfileSelfHosted:
		return validateSelfHosted(c)
	case ProfilePersonal:
		return validatePersonal(c)
	default:
		return errInvalidValue("profile", string(c.Profile),
			"profile must be 'personal' or 'self-hosted'").
			withNext("run: gseer setup  (to choose a profile)")
	}
}

// validateSelfHosted enforces the self-hosted profile schema:
//   - database.* is required (DSN or components).
//   - database.dsn, when set, MUST be a postgres:// connection string
//     (v0.3.2 fix: the mirror of the personal guard — a SQLite file
//     path carried over from a personal config used to pass validation
//     and fail deep inside the PG driver as a confusing
//     E_DB_UNREACHABLE).
//   - client.endpoint / server.* / index.* were removed with the
//     API-server and shared-index surfaces (CLI-only architecture).
func validateSelfHosted(c *Config) *Error {
	if c.Database.DSN == "" && c.Database.Host == "" {
		return errRequired("database.dsn (or database.host+port+user+password+name)", string(ProfileSelfHosted)).
			withWhy("the self-hosted profile requires a PostgreSQL connection.").
			withNext("run: gseer setup --self-hosted --with-compose  (to provision one)")
	}
	if trimmed := strings.TrimSpace(c.Database.DSN); trimmed != "" &&
		!strings.HasPrefix(trimmed, "postgres://") && !strings.HasPrefix(trimmed, "postgresql://") {
		return errInvalidValue("database.dsn", "[redacted]",
			"the self-hosted profile requires a postgres:// connection string in database.dsn — a bare filesystem path is the personal-profile SQLite form").
			withNext("fix database.dsn (postgres://user:pass@host:port/db?sslmode=…), or run: gseer setup --personal  (SQLite file)")
	}
	return nil
}

// validatePersonal enforces the personal-profile schema:
//   - database.dsn is REQUIRED and must be the database FILE path
//     (postgres:// URLs are rejected — wrong engine, wrong profile);
//   - sources may be present (config-only; the collect runner gates on
//     enabled=false by default).
func validatePersonal(c *Config) *Error {
	if c.Database.DSN == "" {
		return errRequired("database.dsn", string(ProfilePersonal)).
			withNext("run: gseer setup  (provisions the database file and writes the config)")
	}
	if strings.HasPrefix(strings.TrimSpace(c.Database.DSN), "postgres://") {
		return errInvalidValue("database.dsn", "[redacted]",
			"the personal profile stores the SQLite database FILE path in database.dsn, not a postgres:// URL").
			withNext("run: gseer setup --personal  (writes the correct config), or switch: gseer setup --self-hosted")
	}
	if c.Database.RuntimeDSN != "" {
		return errProfileConflict("database.runtime_dsn", string(ProfilePersonal)).
			withWhy("personal mode uses ONE local credential — the database file's filesystem permissions (0600).").
			withNext("remove database.runtime_dsn")
	}
	return nil
}
