// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// loader.go — the Load entry point.
//
// Load is the single function that produces a validated *Config.  It
// implements the precedence: CLI flags > environment variables > YAML
// config file > owner-approved defaults (PD-1…PD-9).
//
// The flow:
//
//  1. Resolve the config file path (--config flag > GSEER_CONFIG env >
//     platform default).  If no file exists, proceed with defaults +
//     env + flags only (Source = "env-only").
//  2. Read the file; loose-decode into map[string]any.
//  3. scanForPolicyActive — reject any policy.active.* (AC-7.x).
//  4. scanForUnsafeKeys — reject InsecureSkipVerify etc.
//  5. strictDecode into Config (KnownFields(true) — unknown keys → error).
//  6. applyDefaults — fill in PD-1…PD-9 and v0.0.1 defaults.
//
// Steps 3 and 4 run against the raw map BEFORE strict decode so that
// policy.active.* and unsafe keys produce pointed error messages rather
// than the generic unknown-key error.

// Flags holds the CLI flags that participate in config resolution.
// Only the flags that map to config fields are here; --verbose/--quiet/
// --no-color/--output are CLI state, not config, and are owned by the
// cli package.
type Flags struct {
	// ConfigPath is the --config flag value (path to a YAML file).
	ConfigPath string
	// Profile is the --profile flag value (personal | self-hosted).
	Profile string
}

// Load resolves and validates the configuration.  Returns a *Config or
// an *Error (never a generic error — every failure carries a stable
// E_* code per SPEC-03 §7).
//
// Load order (corrected per owner M2 review Finding 1):
//
//  1. Resolve config path (--config flag > GSEER_CONFIG env > default).
//
//  2. Read file; loose-decode into map[string]any.
//
//  3. scanForPolicyActive — reject any policy.active.* (AC-7.x).
//
//  4. scanForUnsafeKeys — reject InsecureSkipVerify etc.
//
//  5. strictDecode into Config (KnownFields(true) — unknown keys → error).
//
//  6. applyEnv — environment-variable overlay (profile may change).
//
//  7. applyFlags — CLI flag overrides (profile finalized here).
//
//  8. applyDefaults — fill in PD-1…PD-9 and v0.0.1 defaults, based on
//     the FINAL resolved profile (so a CLI --profile=self-hosted after a
//     YAML personal file does NOT inherit personal defaults).
//
//  9. Validate — profile + value validation.
//
// The final precedence: CLI Flags > Environment > YAML > Defaults.
func Load(flags Flags) (*Config, *Error) {
	path, cerr := resolveConfigPath(flags)
	if cerr != nil {
		return nil, cerr
	}

	c := &Config{}

	if path != "" {
		data, rerr := readConfigFile(path)
		if rerr != nil {
			if e, ok := rerr.(*Error); ok {
				return nil, e
			}
			return nil, newError(CodeConfigParse, fmt.Sprintf("cannot read %q", path)).
				withWhy(rerr.Error()).
				withNext("run: gseer doctor")
		}
		c.Source = path

		// Loose decode for the policy.active + unsafe-key scan.
		var raw map[string]any
		if yamlErr := yaml.Unmarshal(data, &raw); yamlErr != nil {
			return nil, errParse(path, yamlErr)
		}
		if e := scanForPolicyActive(raw); e != nil {
			return nil, e
		}
		if e := scanForUnsafeKeys(raw); e != nil {
			return nil, e
		}

		// Strict decode into the typed Config.
		if err := strictDecode(data, c); err != nil {
			if typeErr, ok := err.(*yaml.TypeError); ok {
				fields := typeErr.Errors
				if len(fields) > 0 {
					return nil, errUnknownKey(extractFieldName(fields[0]))
				}
			}
			return nil, errParse(path, err)
		}
	} else {
		c.Source = "env-only"
	}

	// Order matters: env + flags FIRST, so the profile is finalized
	// before applyDefaults fills in profile-dependent defaults (database
	// components for self-hosted).
	applyEnv(c)
	applyFlags(c, flags)
	applyDefaults(c)

	if e := Validate(c); e != nil {
		return nil, e
	}
	return c, nil
}

// applyFlags applies CLI flag overrides (highest precedence).
func applyFlags(c *Config, flags Flags) {
	if flags.Profile != "" {
		c.Profile = Profile(strings.TrimSpace(flags.Profile))
	}
}

// resolveConfigPath determines the config file path in precedence order:
// --config flag > GSEER_CONFIG env > platform default ($GSEER_HOME/config.yaml
// when GSEER_HOME is set, else ~/.gseer/config.yaml — DefaultConfigPath, the
// SAME directory `gseer setup` writes; v0.3.2 fix: the loader used to ignore
// GSEER_HOME, so a portable personal setup wrote a config the loader could
// not find and every following command failed with the misleading
// E_CONFIG_REQUIRED error).  Returns "" if no path resolves
// and no file exists (env-only mode).
func resolveConfigPath(flags Flags) (string, *Error) {
	if flags.ConfigPath != "" {
		if _, err := os.Stat(flags.ConfigPath); err != nil {
			return "", errFileNotFound(flags.ConfigPath)
		}
		return flags.ConfigPath, nil
	}
	if envPath, ok := os.LookupEnv("GSEER_CONFIG"); ok && envPath != "" {
		if _, err := os.Stat(envPath); err != nil {
			return "", errFileNotFound(envPath)
		}
		return envPath, nil
	}
	// Platform default: only return if the file actually exists.
	// (Env-only mode is valid — the zero-configuration first run provisions
	// personal mode and writes the config; see internal/cli/first_run.go.)
	def := DefaultConfigPath()
	if def != "" {
		if _, err := os.Stat(def); err == nil {
			return def, nil
		}
	}
	return "", nil // env-only mode
}

// DefaultDir resolves the platform GSEER state directory — the single
// source of truth for where the CLI writes and the loader reads:
// $GSEER_HOME when set (portable installs), else UserHomeDir/.gseer.
// internal/cli's configDir delegates here; keeping ONE implementation
// prevents the write/read divergence this file's history documents.
func DefaultDir() string {
	if v := os.Getenv("GSEER_HOME"); v != "" {
		return v
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ".gseer"
	}
	return filepath.Join(home, ".gseer")
}

// DefaultConfigPath returns the platform-default config file location:
// $GSEER_HOME/config.yaml when GSEER_HOME is set, else ~/.gseer/config.yaml.
func DefaultConfigPath() string {
	return filepath.Join(DefaultDir(), "config.yaml")
}

// DefaultStateDir resolves the persistent personal-database state
// directory per the XDG state convention: $XDG_STATE_HOME/gseer when
// XDG_STATE_HOME is set and absolute, else $HOME/.local/state/gseer.
//
// FIX (Rev16 personal DB portability): this is the DEFAULT location for
// the personal database FILE, so it deliberately ignores GSEER_HOME and
// TMPDIR.  The old default (~/.gseer/gseer.db, and before that whatever
// a harness pointed GSEER_HOME at — e.g. the /tmp/asdlc-rollback/store.db
// in the owner-acceptance finding, seeded by the v0.3.1-era shared-index
// acceptance scripts) could end up on a recycled tmpfs: the database
// vanished between sessions and looked like a corruption.  A state
// directory under XDG_STATE_HOME or the home directory survives reboots
// and tmpfs cleanup, and nothing in this resolution can ever produce a
// /tmp path.  GSEER_HOME remains an EXPLICIT portable-install override
// (respected wherever it points — the default-DB code only consults
// this function when GSEER_HOME is unset).
func DefaultStateDir() string {
	if v := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); v != "" && filepath.IsAbs(v) {
		return filepath.Join(v, "gseer")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Same honest last resort as DefaultDir: a HOME-less environment
		// is a broken install; keep the CLI runnable instead of panicking.
		return ".gseer"
	}
	return filepath.Join(home, ".local", "state", "gseer")
}

// extractFieldName parses the yaml.v3 TypeError message to extract the
// offending key name.  yaml.v3 formats unknown-field errors as:
//
//	`line N: field X not found in type Y`
//
// We want just `X` (the key name) for the error message.
func extractFieldName(typeErrMsg string) string {
	// Find "field " prefix and " not found" suffix.
	const prefix = "field "
	const suffix = " not found"
	start := strings.Index(typeErrMsg, prefix)
	if start < 0 {
		return typeErrMsg
	}
	start += len(prefix)
	end := strings.Index(typeErrMsg[start:], suffix)
	if end < 0 {
		return typeErrMsg[start:]
	}
	return typeErrMsg[start : start+end]
}
