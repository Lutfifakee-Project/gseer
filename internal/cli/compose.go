// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// compose.go — `gseer setup --with-compose` (QS-2): write the db-only
// docker-compose.yml (the canonical template shipped since M1) and a
// generated .env with a random password, then print the next commands
// verbatim.  Generation never overwrites an existing .env silently and
// never weakens the loopback-only port binding.
//
// --full writes the complete self-hosted stack for the CLI-only
// architecture (v0.3.2): the same PostgreSQL database PLUS a one-shot
// `provision` container that runs the hardened deployment order
// (bootstrap → migrate → grants → audit) and exits — there is NO API/
// dashboard server to run anymore; the headless CLI is the product.
// The full stack deliberately has NO collector container — nothing
// collects uninvoked; collection is
// `docker compose run --rm provision gseer collect run ...` by explicit
// operator action.  Container deployments upgrade by rebuilding the
// image, not via `gseer update` (the image binary is root-owned).

// composeTemplate is the canonical db-only compose (kept byte-identical
// in structure to the repo-root docker-compose.yml shipped in M1).
const composeTemplate = `# GSEER v0.0.1 docker-compose — db only (QS-2).
#
# Written by: gseer setup --with-compose
# Defines ONLY the ` + "`db`" + ` service: PostgreSQL 17-alpine, a named volume,
# a loopback-only port binding, and healthcheck-gated readiness.
# No collector, no egress, no public service.

services:
  db:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${GSEER_DB_USER:-gseer}
      POSTGRES_PASSWORD: ${GSEER_DB_PASSWORD:?set GSEER_DB_PASSWORD in .env}
      POSTGRES_DB: ${GSEER_DB_NAME:-gseer}
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --locale=C.UTF-8"
    ports:
      # Loopback-only: the database is not reachable from other hosts.
      - "127.0.0.1:5432:5432"
    volumes:
      - gseer-db-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${GSEER_DB_USER:-gseer} -d ${GSEER_DB_NAME:-gseer}"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 10s

volumes:
  gseer-db-data:
    name: gseer-db-data
`

// fullComposeTemplate is the v0.3.2 complete self-hosted stack: db +
// one-shot hardened provisioning.  Security posture:
//   - the DB publishes NO host port (compose-internal network only —
//     strictly stronger than the db-only template's loopback bind);
//   - the provision container runs the hardened deployment order
//     (bootstrap → migrate → grants → audit) under the operator
//     credential, sets the least-privilege gseer_app runtime password,
//     and EXITS — there is no serving process to keep alive (CLI-only
//     architecture: the API/dashboard server was removed);
//   - the fail-closed privilege audit refuses an unsafe deployment
//     with exit 5 — there is no bypass.
const fullComposeTemplate = `# GSEER v0.3.2 docker-compose — full self-hosted stack (db + one-shot provision).
#
# Written by: gseer setup --with-compose --full
#
# Services:
#   db         PostgreSQL 17 (compose-internal; NO host port published)
#   provision  one-shot hardened deployment order (bootstrap → migrate →
#              grants → audit), then exits — CLI-only architecture: there
#              is no API/dashboard server container anymore; run the CLI
#              from the host over the published loopback port or with
#              ` + "`docker compose run --rm provision gseer …`" + `.
#
# Hardened credential model (docs/DEPLOYMENT.md): data-plane commands
# prefer the least-privilege gseer_app runtime credential
# (GSEER_DB_RUNTIME_DSN, derived from GSEER_APP_PASSWORD); the operator
# credential provisions.  The audit refuses an unsafe deployment with
# exit 5 — there is no bypass.
#
# Deliberately absent: a collector container and a serving container.
# Nothing collects uninvoked — run
#   docker compose run --rm provision gseer collect run --source <name>
# explicitly, and only for sources whose terms you have reviewed
# (docs/SOURCES.md).  Container deployments upgrade by rebuilding the
# image, not via gseer update (docs/UPDATE.md §1).

services:
  db:
    image: postgres:17-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: ${GSEER_DB_USER:-gseer}
      POSTGRES_PASSWORD: ${GSEER_DB_PASSWORD:?set GSEER_DB_PASSWORD in .env}
      POSTGRES_DB: ${GSEER_DB_NAME:-gseer}
      POSTGRES_INITDB_ARGS: "--encoding=UTF8 --locale=C.UTF-8"
    # No ports section: the database is reachable ONLY from the compose
    # network (the provision service).  Host-side admin/backup:
    #   docker compose exec db pg_dump ...
    volumes:
      - gseer-db-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${GSEER_DB_USER:-gseer} -d ${GSEER_DB_NAME:-gseer}"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 10s

  provision:
    build:
      context: .
      args:
        VERSION: ${GSEER_VERSION:-v0.3.2}
        COMMIT: ${GSEER_COMMIT:-unknown}
    image: gseer:local
    restart: "no"
    depends_on:
      db:
        condition: service_healthy
    # Provision once (hardened order; idempotent on re-runs), then exit.
    # The audit gate refuses an unsafe deployment before completing.
    command: ["sh", "-c", "gseer setup --self-hosted --runtime-password-env GSEER_APP_PASSWORD"]
    environment:
      GSEER_PROFILE: self-hosted
      # Operator credential (provisioning).
      GSEER_DB_DSN: postgres://${GSEER_DB_USER:-gseer}:${GSEER_DB_PASSWORD:?set GSEER_DB_PASSWORD in .env}@db:5432/${GSEER_DB_NAME:-gseer}?sslmode=disable
      # Runtime credential (the least-privilege data-plane identity).
      GSEER_DB_RUNTIME_DSN: postgres://gseer_app:${GSEER_APP_PASSWORD:?set GSEER_APP_PASSWORD in .env}@db:5432/${GSEER_DB_NAME:-gseer}?sslmode=disable

volumes:
  gseer-db-data:
    name: gseer-db-data
`

// fullEnvTemplateFmt is the generated .env for the full stack: database
// credential + the gseer_app runtime password (both random).  GSEER_DSN
// is the HOST-side convenience DSN for bare-metal CLI access over the
// published loopback port (the db-only compose publishes 127.0.0.1:5432);
// the containers themselves use the compose-internal `db` hostname.
// (The API token is gone with the API server — CLI-only architecture.)
const fullEnvTemplateFmt = `# GSEER .env — generated by: gseer setup --with-compose --full
# Both secrets below were randomly generated at write time.
# Keep this file private (chmod 600): it holds the database password
# AND the runtime (gseer_app) password.
GSEER_DB_USER=gseer
GSEER_DB_PASSWORD=%s
GSEER_APP_PASSWORD=%s
GSEER_DB_NAME=gseer
GSEER_VERSION=v0.3.2
# Host-side DSN for CLI tools running OUTSIDE compose.  The runtime DSN
# is derived from GSEER_APP_PASSWORD (docker-compose.full.yml); export
# GSEER_DB_RUNTIME_DSN with it for the least-privilege data plane.
GSEER_DSN=postgres://gseer:%s@127.0.0.1:5432/gseer?sslmode=disable
`

// envTemplate is the generated .env body.  The DSN matches the compose
// loopback binding (host-side port 5432).
const envTemplateFmt = `# GSEER .env — generated by: gseer setup --with-compose
# The database password was randomly generated at write time.
# Keep this file private (it holds the database credential).
GSEER_DB_USER=gseer
GSEER_DB_PASSWORD=%s
GSEER_DB_NAME=gseer
GSEER_DSN=postgres://gseer:%s@127.0.0.1:5432/gseer?sslmode=disable
`

// writeComposeFiles writes ./docker-compose.yml (if absent) and ./.env
// (if absent) into dir.  Returns the actions taken.  An existing .env is
// NEVER overwritten (it may hold a live credential); an existing compose
// file is kept when byte-identical, refused otherwise.
func writeComposeFiles(dir string) (wrote []string, err error) {
	composePath := filepath.Join(dir, "docker-compose.yml")
	envPath := filepath.Join(dir, ".env")

	composeBody := composeTemplate
	if existing, rerr := os.ReadFile(composePath); rerr == nil { // #nosec G304 -- reads the operator's existing compose file for the never-overwrite comparison
		if strings.TrimSpace(string(existing)) != strings.TrimSpace(composeBody) {
			return nil, fmt.Errorf("E_COMPOSE_EXISTS: %s already exists with different content\n"+
				"Why: --with-compose never overwrites an operator-edited compose file\n"+
				"Try: keep the existing file (it already defines the db service) or remove it first", composePath)
		}
	} else if os.IsNotExist(rerr) {
		if werr := os.WriteFile(composePath, []byte(composeBody), 0o644); werr != nil { // #nosec G306 -- no secrets in the compose file; the credential lives in .env (0600)
			return nil, fmt.Errorf("E_COMPOSE_WRITE: cannot write %s: %w", composePath, werr)
		}
		wrote = append(wrote, composePath)
	} else {
		return nil, fmt.Errorf("E_COMPOSE_STAT: %s: %w", composePath, rerr)
	}

	if _, serr := os.Stat(envPath); serr == nil {
		return nil, fmt.Errorf("E_ENV_EXISTS: %s already exists\n"+
			"Why: --with-compose never overwrites an .env (it may hold a live credential)\n"+
			"Try: reuse the existing .env (GSEER_DB_PASSWORD must be set) or remove it first", envPath)
	}
	password, perr := randomPassword()
	if perr != nil {
		return nil, fmt.Errorf("E_COMPOSE_RANDOM: %w", perr)
	}
	envBody := fmt.Sprintf(envTemplateFmt, password, password) // #nosec G101 -- template placeholders filled with the runtime-generated password, not hardcoded credentials
	if werr := os.WriteFile(envPath, []byte(envBody), 0o600); werr != nil {
		return nil, fmt.Errorf("E_COMPOSE_WRITE: cannot write %s: %w", envPath, werr)
	}
	wrote = append(wrote, envPath)
	return wrote, nil
}

// randomPassword returns a 24-hex-char password from crypto/rand.
func randomPassword() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// runSetupWithCompose generates the compose + .env pair and prints the
// next commands verbatim (QS-2).  Runs after a successful --self-hosted
// provisioning OR standalone with --self-hosted.  full=true selects the
// v0.3.2 complete stack (db + one-shot hardened provisioning).
func runSetupWithCompose(cmd *cobra.Command, dir string, full bool) error {
	out := cmd.OutOrStdout()
	var wrote []string
	var err error
	if full {
		wrote, err = writeFullComposeFiles(dir)
	} else {
		wrote, err = writeComposeFiles(dir)
	}
	if err != nil {
		return err
	}
	for _, f := range wrote {
		printf(out, "[ ok  ] wrote %s\n", f)
	}
	if !full {
		printf(out, "\nNext (QS-2):\n")
		printf(out, "  docker compose up -d db                    # DB now running (healthcheck-gated)\n")
		printf(out, "  docker compose ps db                       # expect: healthy\n")
		printf(out, "  gseer setup --self-hosted --db-url \"$(grep '^GSEER_DSN=' .env | cut -d= -f2-)\"\n\n")
		printf(out, "The database binds 127.0.0.1 only; the generated .env holds the credential (chmod 600).\n")
		return nil
	}
	printf(out, "\nNext (full stack, docs/DOCKER.md):\n")
	printf(out, "  docker compose -f docker-compose.full.yml up -d --build   # db (healthcheck-gated) + one-shot hardened provision\n")
	printf(out, "  docker compose -f docker-compose.full.yml ps              # expect: db healthy; provision exits 0 when done\n")
	printf(out, "  export GSEER_PROFILE=self-hosted\n")
	printf(out, "  export GSEER_DB_DSN=\"$(grep '^GSEER_DSN=' .env | cut -d= -f2-)\"\n")
	printf(out, "  export GSEER_DB_RUNTIME_DSN=\"postgres://gseer_app:$(grep '^GSEER_APP_PASSWORD=' .env | cut -d= -f2-)@127.0.0.1:5432/gseer?sslmode=disable\"\n")
	printf(out, "  gseer doctor                                              # expect the fail-closed audit PASS under gseer_app\n\n")
	printf(out, "Posture: the DB publishes NO host port in the full template (compose-internal); the provision container runs the hardened deployment order and exits — there is no API/dashboard server (CLI-only architecture).  The .env holds the secrets (chmod 600).\n")
	printf(out, "Lifecycle (startup/upgrade/backup/recovery): docs/DOCKER.md.\n")
	return nil
}

// writeFullComposeFiles writes ./docker-compose.full.yml + ./.env for the
// complete stack.  Same overwrite-safety contract as writeComposeFiles:
// an existing .env is never replaced (live credentials), an existing
// compose file must be byte-identical or the operator keeps theirs.
func writeFullComposeFiles(dir string) (wrote []string, err error) {
	composePath := filepath.Join(dir, "docker-compose.full.yml")
	envPath := filepath.Join(dir, ".env")

	if existing, rerr := os.ReadFile(composePath); rerr == nil { // #nosec G304 -- reads the operator's existing full-stack compose for the never-overwrite comparison
		if strings.TrimSpace(string(existing)) != strings.TrimSpace(fullComposeTemplate) {
			return nil, fmt.Errorf("E_COMPOSE_EXISTS: %s already exists with different content\n"+
				"Why: --with-compose never overwrites an operator-edited compose file\n"+
				"Try: keep the existing file or remove it first", composePath)
		}
	} else if os.IsNotExist(rerr) {
		if werr := os.WriteFile(composePath, []byte(fullComposeTemplate), 0o644); werr != nil { // #nosec G306 -- no secrets in the compose file; the credential lives in .env (0600)
			return nil, fmt.Errorf("E_COMPOSE_WRITE: cannot write %s: %w", composePath, werr)
		}
		wrote = append(wrote, composePath)
	} else {
		return nil, fmt.Errorf("E_COMPOSE_STAT: %s: %w", composePath, rerr)
	}

	if _, serr := os.Stat(envPath); serr == nil {
		return nil, fmt.Errorf("E_ENV_EXISTS: %s already exists\n"+
			"Why: --with-compose never overwrites an .env (it may hold live credentials)\n"+
			"Try: reuse the existing .env (GSEER_DB_PASSWORD and GSEER_APP_PASSWORD must be set) or remove it first", envPath)
	}
	password, perr := randomPassword()
	if perr != nil {
		return nil, fmt.Errorf("E_COMPOSE_RANDOM: %w", perr)
	}
	appPassword, perr := randomPassword()
	if perr != nil {
		return nil, fmt.Errorf("E_COMPOSE_RANDOM: %w", perr)
	}
	envBody := fmt.Sprintf(fullEnvTemplateFmt, password, appPassword, password) // #nosec G101 -- template placeholders filled with runtime-generated secrets, not hardcoded credentials
	if werr := os.WriteFile(envPath, []byte(envBody), 0o600); werr != nil {
		return nil, fmt.Errorf("E_COMPOSE_WRITE: cannot write %s: %w", envPath, werr)
	}
	wrote = append(wrote, envPath)
	return wrote, nil
}
