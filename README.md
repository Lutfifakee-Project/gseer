# GSEER — Search the Internet.

![GSEER banner](docs/assets/banner.png)

[![CI](https://github.com/Lutfifakee-Project/gseer/actions/workflows/ci.yml/badge.svg)](https://github.com/Lutfifakee-Project/gseer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## What is GSEER?

GSEER is an open-source, **self-hosted search engine for internet assets**.
Local passive discovery gathers public facts (DNS answers, reverse-DNS
names, ASN ownership — plus TLS :443 service facts under an authorized
scope) into your **Local Index**, and every fact is searchable with a
simple query language from ONE interface: the **CLI**.  Install it, run
`gseer setup`, search — no URL to paste, no database server, no crawler
to operate, no hosted service in the loop.

Everything runs on your machine: your discovery, your database, your
data, your rules.  No account, no API key, no shared index, no dashboard,
no website.  A query can only ever READ — searching never collects, and
nothing collects unless you run it (Search ≠ Scan).

## Key features

- **Zero-config first run** — bare `gseer` provisions personal mode: one
  SQLite file (`0600`) at `~/.gseer/gseer.db`, migrations, config — then
  prints exactly how data enters the index.
- **Real data from day one** — `gseer setup` imports the project's central
  versioned, checksummed, Ed25519-signed dataset atomically (checksum
  verification, rollback + recovery on any failure) and bootstraps local
  passive discovery from your egress context (one bounded pass; honest
  `[skip]` when offline).
- **GQL search** — comparisons, booleans, CIDR/domain containment,
  wildcards, free text, facets, per-asset mode, `--explain`/`--validate`.
- **Passive collection on your terms** — `dns`, `ptr`, `ip2asn` are
  reviewed-enabled; provider terms are enforced in code (`E_SOURCE_TERMS`);
  RDAP/CT stay disabled until their terms clear (`docs/SOURCES.md`).
- **Authorized active observation** — `gseer scan http|tls` runs only under
  a live, default-deny scope you registered (`gseer scope add`); every
  decision is audited; denied targets are never touched.
- **Suppression and hygiene** — keep ranges/hosts out of the index
  (`gseer suppress add`); consistent backup/restore (`gseer db backup`).
- **Signed updates** — `gseer update` verifies an Ed25519-signed manifest
  before anything is downloaded or replaced.
- **Fully self-hosted** — personal mode is zero-dependency; a hardened
  PostgreSQL 16+ profile (least-privilege runtime role, fail-closed
  privilege audit) is available for server deployments.

Platform: **Linux only** (AMD64 required, ARM64 best-effort).  Windows and
macOS are not product platforms.

## Installation

Install Go (latest version), then one command:

```bash
go install -v github.com/Lutfifakee-Project/gseer/cmd/gseer@latest
```

The binary lands in `$(go env GOPATH)/bin` — make sure that directory is
on your `PATH`.  Checksum-verified release binaries and build-from-source
instructions: [`docs/INSTALL.md`](docs/INSTALL.md).

Personal mode needs nothing beyond the binary — no database server, no
Docker, no config files to write.

## Quick start

```bash
# 1. Provision + bootstrap real data into your Local Index:
gseer setup
#    → ~/.gseer/gseer.db (one SQLite file, 0600) + ~/.gseer/config.yaml
#    → imports the central dataset (checksum-verified, atomic)
#    → one bounded local discovery pass (honest [skip] offline)

# 2. Search it:
gseer search "port=443"

# 3. Verify the installation and evidence freshness:
gseer doctor

# 4. Refresh the dataset any time WITHOUT a re-setup:
gseer dataset update
```

An unreachable dataset channel degrades to an honest `[warn]` — setup
still exits 0 and your local bootstrap works.  Full walkthrough
(including the self-hosted PostgreSQL profile):
[`docs/QUICKSTART.md`](docs/QUICKSTART.md).

## Search examples

GQL is the GSEER query language.  `=` is sugar for `==`; strings are
double-quoted; numbers are bare integers.

```bash
gseer search 'port=443'
gseer search 'server="nginx" && port=443'
gseer search 'title="phpMyAdmin"'
gseer search 'ip IN_CIDR "203.0.113.0/24"'        # CIDR containment
gseer search 'domain IN_DOMAIN "example.net"'     # apex + subdomains
gseer search 'ANY(host){ http.status == 200 }'    # host has ANY service with 200
gseer search '"wordpress"'                        # bare-keyword free text
gseer search 'ip*="203.0.113.*"'                  # wildcard fuzzy match
gseer search 'after="2026-01-01" && status_code=200'
gseer search 'port==443' --facets                 # facet aggregates
gseer search 'port==443' --mode asset             # one row per asset
gseer search 'port==443' --validate               # validate only, no DB contact
```

Wrong field names get helpful errors ("Unknown field: prt / Did you
mean: port").  The full grammar, operator list, and field registry:
[`docs/SEARCH-SYNTAX.md`](docs/SEARCH-SYNTAX.md).

## Configuration

Zero configuration is required for the basic flow.  When you do want to
configure: precedence is CLI flags > environment variables > YAML config
file > defaults; the file lives at `~/.gseer/config.yaml` (override with
`--config` or `GSEER_CONFIG`).  The annotated set: [`.env.example`](.env.example).

| Variable | Meaning |
| --- | --- |
| `GSEER_HOME` | Portable state directory (config + database live inside it) |
| `GSEER_PROFILE` | `personal` (default) or `self-hosted` |
| `GSEER_DB_DSN` | PostgreSQL DSN (operator credential) for the self-hosted profile |
| `GSEER_DB_RUNTIME_DSN` | Least-privilege runtime DSN (`gseer_app`) |
| `GSEER_DATASET_MANIFEST_URL` | Central dataset channel override (https) |
| `GSEER_UPDATE_MANIFEST_URL` | Signed-update channel |
| `GSEER_POLICY_EVALUATION_FIXTURES` | Standing consent for the fixture load/purge gate |
| `GSEER_FINGERPRINTS_RULES_DIR` / `GSEER_FINGERPRINTS_DISABLED` | Operator fingerprint rules / kill switch |

Handy storage commands:

```bash
gseer db backup --out backup.db   # consistent snapshot (VACUUM INTO), 0600
gseer db restore backup.db        # staged, validated replacement; old DB kept aside
```

Every command has `--help`; `gseer --help` lists the live command set.

## Documentation

- [`docs/QUICKSTART.md`](docs/QUICKSTART.md) — canonical fresh-install walkthrough
- [`docs/INSTALL.md`](docs/INSTALL.md) — install methods, checksums, build from source
- [`docs/SEARCH-SYNTAX.md`](docs/SEARCH-SYNTAX.md) — GQL grammar, operators, field registry
- [`docs/DATASET.md`](docs/DATASET.md) — central dataset channel (pipeline, manifest, atomic import)
- [`docs/SOURCES.md`](docs/SOURCES.md) — data-source review register (what data comes from where)
- [`docs/SCANNING.md`](docs/SCANNING.md) — authorized active observation and the scope gateway
- [`docs/RULES.md`](docs/RULES.md) — fingerprint rule format (easy contribution path)
- [`docs/UPDATE.md`](docs/UPDATE.md) — the signed-update chain
- [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) — common errors and recovery
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — self-hosted PostgreSQL deployment
- [`docs/DOCKER.md`](docs/DOCKER.md) — the Docker self-hosted stack
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — release register and honest non-goals
- [`CHANGELOG.md`](CHANGELOG.md) — per-release changes

## License

MIT — see [`LICENSE`](LICENSE) (migrated from AGPL-3.0 as of v0.3.2 —
[`docs/releases/LICENSE-MIGRATION-v0.3.2.md`](docs/releases/LICENSE-MIGRATION-v0.3.2.md)).
Third-party components: [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
Contributions welcome: fingerprint rules ([`docs/RULES.md`](docs/RULES.md))
are the easiest starting point.
