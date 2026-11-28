# GSEER — Installation (v0.3.3, Linux-only)

Platform policy (v0.3.2 architecture decision): **Linux only** — AMD64 is
the required product platform, ARM64 ships best-effort.  There are no
Windows or macOS binaries, packages, or acceptance requirements.

## Install method: RC prerelease ZIP + `make build` (recommended for v0.3.3-rc2)

v0.3.3-rc2 is a release candidate: **its Git tag does not exist yet**
(`go list -m -versions` tops out at v0.3.3-rc1), so `go install
…@v0.3.3-rc2` cannot resolve (`invalid version: unknown revision
v0.3.3-rc2`).  The verified RC install path is the published source ZIP:

```bash
# 1. download gseer-v0.3.3-rc2-docfix2.zip (and its .sha256 sidecar)
sha256sum -c gseer-v0.3.3-rc2-docfix2.zip.sha256   # 2. verify (di folder distribusi)
unzip gseer-v0.3.3-rc2-docfix2.zip                 # 3. extract
cd gseer-v0.3.3-rc2                                # 4. enter the source tree
make build                                         # 5. build (VERSION defaults to v0.3.3-rc2)
./bin/gseer version                                # 6. must print: gseer v0.3.3-rc2
```

Nothing else is required for personal mode: `gseer setup` provisions the
single-file database and config (and so does the first engine command —
`search`, `source add`, `collect run` — when no configuration exists
yet).

## Install method: `go install` (versions that already have a Git tag)

Once a version is published WITH its Git tag, a pinned `go install`
works and is reproducible.  Example — the newest TAGGED version today:

```bash
go install github.com/Lutfifakee-Project/gseer/cmd/gseer@v0.3.3-rc1
gseer version   # expect: gseer v0.3.3-rc1
```

The binary lands in `$(go env GOPATH)/bin` — put that on your `PATH` if
it is not.

For **v0.3.3-rc2 this path is NOT available** (no tag yet — use the ZIP
method above).  Two look-alike commands do not install it either:
`@latest` resolves to the newest NON-prerelease tag (currently v0.3.1)
and can never install a release candidate, and `go install ./cmd/gseer`
builds whatever working tree it is run in with an honest `gseer dev`
version — neither is an RC install path.
Note on `version` output: `go install` builds carry no VCS metadata, so
`commit`/`built_at` read "unknown" — the version itself is correct.

## Install method: build from source (development)

| Component | Requirement |
| --- | --- |
| Go | 1.26+ (per `go.mod`) |
| PostgreSQL | **16+** ONLY for the developer self-hosting internals (NOT the official product path — the CLI needs nothing but the binary; OD-7 floor enforced by `gseer setup` and `gseer doctor`; verified end-to-end on **16.15 and 17.2**; the compose files ship `postgres:17-alpine`) |
| OS | Linux (AMD64 required; ARM64 best-effort) |

```bash
git clone https://github.com/Lutfifakee-Project/gseer.git
cd gseer
make build                  # ./bin/gseer (version stamped via ldflags)
make tools                  # install golangci-lint + govulncheck
make check                  # build + vet + lint + test + vuln
./bin/gseer version         # prints the version the Makefile stamps
```

`git clone` checks out the current development state of `main` — since
v0.3.3-rc2 has no Git tag, a clone is NOT the RC2 source snapshot, and
`make build VERSION=…` only changes the stamped string, not the source.
The only verified v0.3.3-rc2 source state is the released ZIP (method
above).  In the released package the Makefile default is
`VERSION=v0.3.3-rc2`, so a plain `make build` stamps exactly that.

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
sha256sum -c gseer-v0.3.3-rc2-docfix2.zip.sha256   # Linux (di folder distribusi)
```

## Docker image (built locally, not pulled from a registry)

```bash
docker build --build-arg VERSION=v0.3.3-rc2 -t gseer:local .   # from the extracted RC package
# or let the full stack build it for you:
gseer setup --with-compose --full
docker compose -f docker-compose.full.yml up -d --build
```

There is no official GSEER image in any container registry for v0.3.3-rc2;
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
