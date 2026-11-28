# GSEER — Installation (v0.3.2, Linux-only)

Platform policy (v0.3.2 architecture decision): **Linux only** — AMD64 is
the required product platform, ARM64 ships best-effort.  There are no
Windows or macOS binaries, packages, or acceptance requirements.

## Install method: `go install` (recommended)

Install Go (latest version), then:

```bash
go install github.com/Lutfifakee-Project/gseer/cmd/gseer@latest
```

The binary lands in `$(go env GOPATH)/bin` — put that on your `PATH` if
it is not.  Verify the installation:

```bash
gseer version   # expect: gseer v0.3.2
```

Nothing else is required for personal mode: `gseer setup` provisions the
single-file database and config (and so does the first engine command —
`search`, `source add`, `collect run` — when no configuration exists yet).

Pin a release instead of `@latest` when you want reproducibility, e.g.
`go install github.com/Lutfifakee-Project/gseer/cmd/gseer@v0.3.2`.
Note on `version` output: `go install` builds carry no VCS metadata, so
`commit`/`built_at` read "unknown" — the version itself is correct.

## Install method: build from source

| Component | Requirement |
| --- | --- |
| Go | 1.26+ (per `go.mod`) |
| PostgreSQL | **16+** ONLY for the developer self-hosting internals (NOT the official product path — the CLI needs nothing but the binary; OD-7 floor enforced by `gseer setup` and `gseer doctor`; verified end-to-end on **16.15 and 17.2**; the compose files ship `postgres:17-alpine`) |
| OS | Linux (AMD64 required; ARM64 best-effort) |

```bash
git clone https://github.com/Lutfifakee-Project/gseer.git
cd gseer
make build VERSION=v0.3.2   # ./bin/gseer (version stamped via ldflags)
make tools                  # install golangci-lint + govulncheck
make check                  # build + vet + lint + test + vuln
./bin/gseer version         # expect: gseer v0.3.2
```

The resulting `./bin/gseer` binary's SHA-256 can be printed with
`gseer doctor` for diagnostic purposes.  It is a self-reported running
binary fingerprint and must NOT be compared against a source-archive
SHA-256 checksum — those are different artifacts.  Release artifacts are
published with a `checksums.txt` manifest (SHA-256,
artifact-per-artifact); verify any artifact you download against it.
`make build` is reproducible: two builds from a clean clone with the
same toolchain and flags produce byte-identical binaries (verified this
release).

## Verify the source archive

```bash
sha256sum -c GSEER-v0.3.2-source.zip.sha256   # Linux
```

## Docker image (built locally, not pulled from a registry)

```bash
docker build --build-arg VERSION=v0.3.2 -t gseer:local .
# or let the full stack build it for you:
gseer setup --with-compose --full
docker compose -f docker-compose.full.yml up -d --build
```

There is no official GSEER image in any container registry for v0.3.2;
the image is built locally from the source.  The full stack (db,
healthchecks, persistent volume) and its lifecycle — startup, upgrade,
backup/restore, recovery — are documented in `docs/DOCKER.md`.

## After install

`gseer setup` provisions the personal Local Index AND auto-imports the
central dataset (`docs/DATASET.md`): the manifest is fetched, the payload
checksum-verified, and the import applied atomically — no manual seeds,
no manual database work.  The dataset channel is owner-published; while
no release assets are available yet, setup reports the honest channel
warning (e.g. HTTP 404 / `E_DATASET_UNREACHABLE`) and the index simply
starts empty — search stays local and never fabricates results.  Manage
the channel afterwards: `gseer dataset check` (latest manifest: version,
freshness, provenance), `gseer dataset status` (installed state),
`gseer dataset update` (explicit refresh; no re-setup needed).

Continue with `docs/QUICKSTART.md` — the zero-infrastructure path:
`gseer setup` (provisions personal mode and bootstraps local passive
discovery from your egress context) → `gseer search "port=443"`.
The developer self-hosting path (headless CLI over PostgreSQL) and its
credential model: `docs/DEPLOYMENT.md`.  Upgrading an existing
deployment: `docs/UPDATE.md`.
