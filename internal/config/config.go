// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package config

import (
	"net"
	"net/url"
	"strconv"
)

// config.go — the Config struct hierarchy and supported profile types.
//
// The Config is the single in-memory representation produced by Load().
// Every surface (the GSEER CLI) reads from the same Config so that
// precedence and validation are applied once, at load time.
//
// v0.3.2 architecture decision (owner): CLI-ONLY product.  The client
// (remote-endpoint) profile, the server.* settings (API + dashboard),
// and the shared-index channel were removed — the profiles are
// personal (embedded SQLite Local Index) and self-hosted (headless CLI
// over PostgreSQL).

// Profile is the deployment profile (SPEC-03 §5).
type Profile string

const (
	// ProfileSelfHosted runs the CLI engine headless over PostgreSQL.
	// Migrations run on setup --self-hosted.
	ProfileSelfHosted Profile = "self-hosted"
	// ProfilePersonal runs the full engine against ONE embedded SQLite
	// database file (checkpoint B): no PostgreSQL, no separate service.
	// database.dsn holds the database FILE path (not a postgres URL);
	// first-run provisioning is `gseer setup` (personal by default).
	ProfilePersonal Profile = "personal"
)

// Config is the validated, in-memory configuration.
type Config struct {
	Profile      Profile            `yaml:"profile"`
	Database     DatabaseConfig     `yaml:"database"`
	Policy       PolicyConfig       `yaml:"policy"`
	Log          LogConfig          `yaml:"log"`
	Sources      []SourceConfig     `yaml:"sources"`
	Defaults     DefaultsConfig     `yaml:"defaults"`
	Fingerprints FingerprintsConfig `yaml:"fingerprints"`
	Update       UpdateConfig       `yaml:"update"`
	Dataset      DatasetConfig      `yaml:"dataset"`

	// Source is the file path the config was loaded from, or "env-only"
	// when no file was present (defaults + env + flags only).  Set by
	// Load; not part of the YAML schema.
	Source string `yaml:"-"`
}

// DatasetConfig points the CLI at the central internet-asset dataset
// channel (v0.3.2 Rev 9 — the owner-mandated central distribution).
//
// The dataset is a VERSIONED, CHECKSUMMED export of validated passive
// discovery evidence, produced by the project's scheduled GitHub Actions
// pipeline (`.github/workflows/dataset.yml`) and published as release
// artifacts.  `gseer setup` and `gseer dataset update` download the
// manifest, verify the checksum, and import the payload into the Local
// Index through the SAME ingestion path every other writer uses (same
// suppression gate, same delivery-identity dedupe, provenance preserved).
// Search stays LOCAL: the dataset only FEEDS the index — there is no
// shared-index query service to depend on.
//
// Integrity model (P0-1, v0.3.2): the manifest is SIGNED with Ed25519 —
// every consumer verifies the signature against the keyring embedded in
// its binary BEFORE downloading the payload (fail-closed); the payload
// SHA-256 in the signed manifest binds the payload bytes, and a
// checksum mismatch refuses the import outright.
type DatasetConfig struct {
	// ManifestURL is the dataset manifest location.  Empty means the
	// official project channel (OfficialDatasetManifestURL).  Plain
	// http:// is accepted ONLY for loopback hosts (local testing).
	ManifestURL string `yaml:"manifest_url"`
	// TrustedRedirectHosts explicitly allows the dataset fetcher to
	// follow a redirect to these hosts (R4 P0-5; cross-host hops are
	// otherwise refused).  UNSET (key absent) keeps the product default:
	// the GitHub release-asset CDN hosts the official project channel
	// redirects to (release-assets.githubusercontent.com and the legacy
	// objects.githubusercontent.com).  When SET, the list replaces the
	// default wholesale — exact hostnames only (case-insensitive, ports
	// are not part of the match, no wildcards); an empty list trusts
	// nothing.  Trust never bypasses the transport rules, the
	// prohibited-destination check, or the signature/checksum
	// verification of the downloaded artifact.
	TrustedRedirectHosts []string `yaml:"trusted_redirect_hosts"`
}

// OfficialDatasetManifestURL is the default central-dataset manifest
// location: the rolling `central-dataset` GitHub release maintained by
// the project's scheduled dataset pipeline.  That release is deliberately
// kept NON-latest so the binary releases remain the headline "Latest"
// release; the manifest inside it is replaced per dataset version.
const OfficialDatasetManifestURL = "https://github.com/Lutfifakee-Project/gseer/releases/download/central-dataset/gseer-dataset-manifest.json"

// DatabaseConfig holds the PostgreSQL connection settings (PD-8).
type DatabaseConfig struct {
	// DSN is the full connection string.  When set, it overrides the
	// component fields below.  Format:
	//   postgres://user:password@host:port/dbname?sslmode=disable
	// This is the OPERATOR credential (database owner / migration
	// executor) in the v0.2.0 dual-credential model.
	DSN string `yaml:"dsn"`
	// RuntimeDSN (v0.2.0 M-B) is the least-privilege RUNTIME credential
	// — the `gseer_app` login role provisioned by the hardened
	// deployment order (bootstrap → migrate → grants → audit).
	// CLI data-plane commands prefer it and say so explicitly when they
	// fall back to the operator credential.
	RuntimeDSN string `yaml:"runtime_dsn,omitempty"`
	// Component fields (used when DSN is not set).
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	User     string `yaml:"user"`
	Password string `yaml:"password,omitempty"` // never logged
	Name     string `yaml:"name"`
	// SSLMode controls connection encryption.  Loopback-only deployments
	// may use "disable"; non-loopback MUST use "require" or "verify-full".
	SSLMode string `yaml:"sslmode"`
	// MigrationLockTimeoutMs bounds how long the migration runner waits
	// for the migration advisory lock before failing with
	// DB_MIGRATION_LOCK_TIMEOUT.  Implemented as a session-scoped
	// statement_timeout inside the migration driver's Lock(): it covers
	// ONLY the pg_advisory_lock acquisition and is reset to 0 (verified)
	// before any migration SQL runs — slow migrations are never killed
	// by the lock-wait limit.  Range 1000..300000 ms; default
	// DefaultMigrationLockTimeoutMs (applied for explicit-DSN configs
	// too — see applyDatabaseDefaults).  Used by the storage layer
	// (internal/storage/postgres/lock.go + migratedriver.go).
	MigrationLockTimeoutMs int `yaml:"migration_lock_timeout_ms"`
}

// PolicyConfig holds policy switches.  The `active` sub-section is
// INTENTIONALLY ABSENT — any policy.active.* key is rejected at load
// time with E_CONFIG_POLICY_ACTIVE_REJECTED (AC-7.x).
type PolicyConfig struct {
	// EvaluationFixtures gates `setup --load-fixtures` (QS-6).  Default
	// false on non-dev installs; when false, the loader refuses with a
	// confirmation prompt.
	EvaluationFixtures bool `yaml:"evaluation_fixtures"`
}

// LogConfig holds slog settings.
type LogConfig struct {
	Level  string `yaml:"level"`  // debug | info | warn | error
	Format string `yaml:"format"` // text | json
}

// FingerprintsConfig controls the v0.1.0 fingerprint rule engine
// (internal/fprule).  The engine classifies technology evidence that a
// stored observation ALREADY carries into `fingerprint.technologies` —
// it never produces observations and never contacts the network.
type FingerprintsConfig struct {
	// Disabled turns OFF rule-derived technology enrichment at
	// ingestion.  Zero value false = enabled (the useful default); the
	// inverted name avoids the YAML bool zero-value trap.
	Disabled bool `yaml:"disabled"`
	// RulesDir optionally loads operator-contributed rules on top of
	// the embedded seed set (contribution format: docs/RULES.md).  A
	// broken operator rule disables the registry — fail-closed, never
	// a silent no-op.
	RulesDir string `yaml:"rules_dir"`
}

// UpdateConfig points the updater at the signed release channel.
type UpdateConfig struct {
	// ManifestURL is the signed update manifest location (https URL or
	// local path).  The manifest MUST carry an Ed25519 signature that
	// verifies against the key embedded in the binary — the URL alone
	// proves nothing (docs/UPDATE.md).
	ManifestURL string `yaml:"manifest_url"`
}

// SourceConfig is a registered data source (config-only in v0.0.1;
// never collected).  The collection framework lands in v0.0.2.
type SourceConfig struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`     // e.g. "ct", "rdap", "dns"
	Endpoint string `yaml:"endpoint"` // the source's API URL (passive)
	Enabled  bool   `yaml:"enabled"`  // always false in v0.0.1 runtime
}

// DefaultsConfig records the owner-approved engineering defaults.
// PD-1 (search mode) is used by v0.0.1 runtime.  PD-2…PD-7 are recorded
// here as v0.0.2 planning defaults; NO v0.0.1 runtime code path reads
// them.  The owner's directive: "PD-2 through PD-7 are approved as
// engineering defaults only, not authorization to scan."
type DefaultsConfig struct {
	// SearchMode (PD-1) — the default GQL search mode.  Used by v0.0.1.
	SearchMode string `yaml:"search_mode"`
	// CollectionPorts (PD-2) — v0.0.2 planning default.  NOT used in v0.0.1.
	CollectionPorts []int `yaml:"collection_ports"`
	// Protocols (PD-3) — v0.0.2 planning default.  NOT used in v0.0.1.
	Protocols []string `yaml:"protocols"`
	// AuditSpoolBytes (PD-4) — v0.0.2 planning default.  NOT used in v0.0.1.
	AuditSpoolBytes int `yaml:"audit_spool_bytes"`
	// EmergencyReserveBytes (PD-5) — v0.0.2 planning default.  NOT used in v0.0.1.
	EmergencyReserveBytes int `yaml:"emergency_reserve_bytes"`
	// DecompressedCapBytes (PD-6) — v0.0.2 planning default.  NOT used in v0.0.1.
	DecompressedCapBytes int `yaml:"decompressed_cap_bytes"`
	// DecompressedCapMaxBytes (PD-7) — v0.0.2 planning default.  NOT used in v0.0.1.
	DecompressedCapMaxBytes int `yaml:"decompressed_cap_max_bytes"`
	// PostgresMajor (PD-8) — minimum supported PostgreSQL version.  Used by doctor (M3).
	PostgresMajor int `yaml:"postgres_major"`
}

// EffectiveDSN returns the connection string to use, preferring the
// explicit DSN over the component fields.  Used by the storage layer
// (M3) and the doctor reachability check (M3/M11).
//
// When building from components, the password is percent-encoded via
// net/url so that special characters (@, :, /, ?, #, spaces, quotes) are
// handled correctly.  Manual string interpolation would produce a
// malformed DSN for such passwords (owner M2 review Finding 4).
//
// Exported in M3: the storage layer (internal/storage/postgres) and the
// `gseer db migrate` / `doctor` commands resolve the operator's DSN
// through this single method so precedence (DSN > components) lives in
// exactly one place.  The raw result embeds the password — callers must
// pass it only to connection APIs and use postgres.RedactDSN for any
// display (M2/M3 logging restrictions).
func (d DatabaseConfig) EffectiveDSN() string {
	if d.DSN != "" {
		return d.DSN
	}
	sslmode := d.SSLMode
	if sslmode == "" {
		sslmode = "disable" // loopback default
	}
	return fmtDSN(d.User, d.Password, d.Host, d.Port, d.Name, sslmode)
}

// RuntimeCredentialDSN returns the connection string the RUNTIME data
// plane (server, search, collect, suppress, export, host) should use.
// The second return reports whether the runtime credential was EXPLICITLY
// configured (runtime_dsn / GSEER_DB_RUNTIME_DSN):
//
//	explicit=true  → hardened path: connect as gseer_app (least privilege).
//	explicit=false → the deployment has not been provisioned with the
//	  hardened role model; callers decide their own policy (the server
//	  refuses; CLI commands fall back to the operator DSN with an
//	  explicit notice — never silently).
func (d DatabaseConfig) RuntimeCredentialDSN() (dsn string, explicit bool) {
	if d.RuntimeDSN != "" {
		return d.RuntimeDSN, true
	}
	return d.EffectiveDSN(), false
}

// fmtDSN builds a postgres URL-format DSN from components using net/url
// for proper percent-encoding of the userinfo (user, password).  This
// correctly handles passwords containing @, :, /, ?, #, spaces, quotes,
// and other URI-special characters.
//
// Host handling uses net.JoinHostPort, which brackets IPv6 hosts
// automatically ([::1]:5432) and passes IPv4/hostname forms through
// unchanged (host:5432).  Manual Sprintf interpolation would produce an
// ambiguous, unparseable host for IPv6 (::1:5432) — owner DSN review.
//
// Format: postgres://user:password@host:port/dbname?sslmode=...
func fmtDSN(user, password, host string, port int, name, sslmode string) string {
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(user, password),
		Path:   name,
	}
	if port > 0 {
		// net.JoinHostPort brackets IPv6 literals (::1 → [::1]:port)
		// and leaves IPv4/hostname forms unchanged (127.0.0.1:port).
		u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	} else {
		u.Host = host
	}
	q := u.Query()
	q.Set("sslmode", sslmode)
	u.RawQuery = q.Encode()
	return u.String()
}
