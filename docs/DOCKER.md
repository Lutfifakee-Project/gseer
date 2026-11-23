# GSEER — Self-Hosted Docker Stack

> **Fully self-hosted, CLI-only.**  The GSEER CLI talks to PostgreSQL
> directly; there is NO API/dashboard server container.  This document
> describes the Docker deployment of the self-hosted PostgreSQL
> profile: PostgreSQL plus a one-shot hardened provisioning container.
> Personal mode (the zero-config default) needs none of this — one
> SQLite file.

The full stack is **two services**: PostgreSQL 17 (compose-internal,
no host port) and a one-shot `provision` container that runs the
hardened deployment order (bootstrap → migrate → runtime grants →
privilege audit) under the operator credential and EXITS.  Nothing
serves traffic — the CLI talks to PostgreSQL directly.  There is no
collector container (nothing collects uninvoked; collection is an
explicit command) and no API token (there is no API).

## 1. Startup (short workflow)

```
# 1. generate compose + .env (random DB password + random gseer_app password)
gseer setup --with-compose --full

# 2. build + start (db starts first; provision waits for a HEALTHY db)
docker compose -f docker-compose.full.yml up -d --build

# 3. verify
docker compose -f docker-compose.full.yml ps           # db: healthy; provision: exited 0
docker compose -f docker-compose.full.yml logs provision  # audit PASS lines
```

Then run the CLI from the host (the hardened `provision` run printed
the `gseer_app` runtime DSN once — store it):

```
export GSEER_PROFILE=self-hosted
export GSEER_DB_DSN="$(grep '^GSEER_DSN=' .env | cut -d= -f2-)"
export GSEER_DB_RUNTIME_DSN='postgres://gseer_app:<password>@127.0.0.1:5432/gseer?sslmode=disable'
gseer doctor                       # expect the fail-closed audit PASS under gseer_app
gseer search 'port == 443'
```

Or run CLI commands inside the compose network:

```
docker compose -f docker-compose.full.yml run --rm provision gseer search 'port == 443'
```

Load the labeled synthetic corpus (evaluation; NOT real data):

```
docker compose -f docker-compose.full.yml run --rm provision gseer setup --load-fixtures
```

## 2. Security posture (what the template enforces)

- **DB publishes no host port.**  The database is reachable only on the
  compose-internal network from the `provision` service — strictly
  stronger than a loopback bind.  Admin/backup access goes through
  `docker compose exec db psql ...`.
- **`.env` holds all secrets** (database password + the `gseer_app`
  runtime password), written `0600`, never overwritten by a re-run.
  No API token exists — the API server was removed with the CLI-only
  architecture.
- **Non-root runtime user** (uid 10001) in the image; no build tools in
  the final layer; `CGO_ENABLED=0` static binary; default command
  `gseer --help` (no long-running server).
- The fail-closed effective-privilege audit runs inside `provision`;
  a failed audit exits 5 and names every failure
  (`docs/DEPLOYMENT.md` §3.5).

## 3. Upgrade

Container deployments upgrade by **rebuilding the image** — not via
`gseer update` (the container binary is root-owned and read-only for
the runtime user; docs/UPDATE.md §1).

```
git pull                                  # or fetch the new release source
docker compose -f docker-compose.full.yml up -d --build
```

Schema migrations are part of the provisioning step (the hardened
deployment order: bootstrap → migrate → grants → audit); the audit
refuses an incomplete or unsafe schema.  Downgrade = restore the
previous image AND the database backup taken before the upgrade
(migrations are not auto-reversed).

## 4. Backup and restore

The index state lives in the `gseer-db-data` volume, owned by
PostgreSQL.  Backup with standard tooling (consistent, includes
everything: assets, observations, suppressions, collection
bookkeeping):

```
# backup (custom format, compressed)
docker compose -f docker-compose.full.yml exec db \
  pg_dump -U gseer -Fc gseer > gseer-backup-$(date +%Y%m%d).dump

# restore into a fresh volume
docker compose -f docker-compose.full.yml down
docker volume rm gseer-db-data
docker compose -f docker-compose.full.yml up -d db
sleep 10   # wait for healthy: docker compose ... ps
cat gseer-backup-YYYYMMDD.dump | \
  docker compose -f docker-compose.full.yml exec -T db \
  pg_restore -U gseer -d gseer --clean --if-exists
docker compose -f docker-compose.full.yml run --rm provision   # re-run the hardened provisioning
```

## 5. Clean shutdown and recovery

```
docker compose -f docker-compose.full.yml stop     # SIGTERM → graceful stop
docker compose -f docker-compose.full.yml start
docker compose -f docker-compose.full.yml down     # remove containers, KEEP the volume
```

Recovery scenarios:

| Symptom | Action |
| --- | --- |
| `provision` exited non-zero | `docker compose logs provision` — the hardened order failed (most commonly the DB was not healthy yet, or the audit found a real deployment problem); fix per `docs/DEPLOYMENT.md` §3.5 and re-run: `docker compose -f docker-compose.full.yml run --rm provision` |
| `db` unhealthy | check the volume (`docker volume inspect gseer-db-data`) and disk space; PostgreSQL logs are in `docker compose logs db` |
| `.env` lost | secrets are unrecoverable by design — regenerate with `setup --with-compose --full` after moving the old volume aside, or restore from a known `.env` backup |
| migration failed mid-provisioning | repair with `gseer db migrate diagnose` / `force` inside the compose network: `docker compose run --rm provision gseer db migrate diagnose` |

## 6. Data and collection boundaries (unchanged in containers)

- No connector runs automatically: no daemon, no cron, no sidecar.
  `docker compose run --rm provision gseer collect run --source <name>`
  is the operator's explicit action, gated by the same terms register
  (`docs/SOURCES.md`, `E_SOURCE_TERMS`).
- Suppression, fixture-purge isolation, and the asset-only honesty
  contract apply identically inside the container.
- RDAP/CT remain disabled pending provider authorization.
