# GSEER — Changelog

All notable changes per release.  Format: Keep-a-Changelog-ish, newest
first.  Versions follow semver (three-component).

> Provider-identity policy: `docs/SOURCES.md` is the one official
> provider register — external data providers are named only there,
> because data provenance must be transparent.  Entries for shipped
> releases are historical records and keep the provider mentions they
> shipped with; pending sections and all active documentation follow
> the register-only policy.

## [v0.3.3-rc1] — 2026-11-27: resilient pipeline, layered sources, measured quality

Extends the accepted v0.3.2-rc2 state per the expanded master mandate
(six requirement blocks): dataset metrics, layered sources, mature
search proofs, resilient pipeline, measured quality, real-condition
acceptance.  Identity: `gseer v0.3.3-rc1`.

### Added
- **Passive DNS layer (R2):** connector `pdns` (docs/SOURCES.md §J) with
  two reviewed-enabled providers — HackerTarget hostsearch (published
  resolution pairs) and Wayback CDX (published hostname history);
  per-seed failure isolation, free-tier quota messages are errors, and
  the registry/source commands accept the new type.
- **Measured coverage (R1):** `gseer coverage` now reports distinct
  ports/protocols/ASN orgs, observations by asset kind, data age
  (oldest/newest), per-source data states (active ≤7d / stale / failed /
  not_available), cross-source duplication (assets seen by ≥2 distinct
  sources, with the top examples), and per-country / per-ASN breakdowns
  — computed from the real index, never claims about the Internet.
- **Pipeline resilience (R4):** `dataset update` retries transient
  failures (HTTP 429/5xx, transport errors) with exponential backoff;
  interrupted payload downloads RESUME via HTTP Range (checksum + size
  verified over the complete artifact, corrupt tail refused and
  discarded); downgrades are an explicit `E_DATASET_DOWNGRADE` refusal;
  `gseer dataset history` lists previously imported versions (from the
  per-import collection_jobs rows — no schema change).
- **Measured quality (R5):** `gseer bench scale` measures the REAL
  dataset import path (rows/s, wall time, DB size, RSS delta, search
  p50/p95) at 1x/10x/100x corpus scale in isolated databases;
  `gseer bench quality` scores the production search service against
  labeled ground truth (precision/recall/F1 per query); a leakage test
  proves two provisioned stores share nothing.
- **Search mastery proofs (R3):** labeled tests pin field coverage
  (ip/CIDR/domain/hostname/ASN/port/service/technology), operator
  combinations (&&, IN, negation, OR), exact-vs-prefix with relevance
  ordering, cross-entity domain joins, cursor pagination without
  dup/miss, sorting, limits — and JSON/CSV/NDJSON renderers are proven
  to agree on the same row set.

### Changed
- Registry test pins 10 connectors (pdns joins).
- `dataset update` no-op message now states "no payload downloaded".

## [Unreleased] — Rev 13: final production release package (distribution chain closed)

No architecture, product, or scope changes; owner constraints unchanged
(CLI-only, Linux-only, Local Index, central versioned dataset, no
shared-index service/dashboard/website/API server; search never
triggers discovery).  Rev 12 accepted as baseline; not repeated.

### Fixed (workflow finalization — the two real gaps)

- `.github/workflows/dataset.yml`: the dataset version is now monotonic
  ON THE CHANNEL, not on the run counter — the run fetches the published
  official manifest first and publishes `max(run_number, published + 1)`
  (fresh channel = the run number starts the line).  A migrated
  repository or replayed history can no longer publish a version users
  already consume (which would make every installed index NEWER than the
  channel and silently pin `gseer dataset update` on the version gate).
- Upload ordering: the PAYLOAD is uploaded before the MANIFEST — the
  manifest upload is the version commit point.  A read that straddles
  the asset swap (manifest and payload from different versions) is
  honestly rejected by the CLI's checksum verification
  (`E_DATASET_CHECKSUM`) and a retry succeeds.

### Docs

- Harness J03 assertions made dataset-agnostic: the acceptance requires
  a minimum count of REAL `:443/tcp` evidence rows, never specific IPs
  from one build (fresh discovery from a different vantage honestly
  shifted which seed hosts answer TLS — dns.google/one.one.one.one were
  unanswered in the Rev 13 run's vantage; absence recorded, not
  fabricated).

- `docs/INSTALL.md`: documents that `gseer setup` auto-imports the
  central dataset (checksum-verified, atomic; no seeds, no manual DB)
  and the `gseer dataset check/status/update` channel commands, with the
  honest behavior while owner assets are not yet published.

### Pipeline evidence (Rev 13 acceptance)

The ENTIRE chain was exercised end-to-end locally at production
fidelity, mirroring the workflow command-for-command: scheduled-style
passive discovery over the seed register (DNS + audited TLS :443) →
evidence validation → versioned dataset build (v105 = accepted v104 + 1
under the continuity rule) → publication gate (validate) → local
production-fidelity release channel → CLI auto-import + `dataset update`
(version-gated, checksum-verified, atomic) → Local Index → local search
with real results.  See TEST-EVIDENCE.txt.  Production GitHub Release
consumption remains PENDING (official URL 404 at acceptance time) — NOT
claimed.

## [Unreleased] — Rev 12: acceptance harness finalization (targeted; no product changes)

No architecture, product, or scope changes; owner constraints unchanged.
Rev 11 engineering accepted as baseline; not repeated.

### Added

- `pipeline/acceptance-journey.sh` + `pipeline/acceptance-https-channel.py`
  — the product-acceptance harness as a repo artifact.  Fixes the Rev 11
  harness defects found in its journey logs:
  - domain/hostname GQL corrected and baked in (`domain=="host"`,
    `hostname CONTAINS "term"`); a bare term is invalid per the GQL field
    registry and is no longer used.
  - every command runs raw (no masking pipes, `set -o pipefail`); a
    failed search now surfaces its REAL nonzero exit and fails the
    acceptance result.
  - every step asserts on output CONTENT (result counts, expected rows,
    required error classes), so a CLI exit 0 with an embedded failure
    (e.g. setup's loud dataset warning) can never pass unnoticed.
  - the offline step kills channels by port (`fuser -k`), never by a
    pattern that could match the harness's own command line (the Rev 11
    `pkill -f` self-kill that truncated journey-2.log).
  - the final step records the official production URL state honestly:
    `pending` = typed HTTP 404 from the real channel (publication NOT
    claimed) or `live` = actual public GitHub Release consumption — and
    fails on anything else.

### Packaging note

The Rev 11 working tree was restored from the Rev 11 backup after a
sandbox recycle (sources verified byte-identical via the cumulative
patch; owner baseline 390079e reconstructed by reverse-applying it).

## [Unreleased] — Rev 11: real coverage expansion, production-fidelity distribution validation, real user journey

No architecture, product, or scope changes; owner constraints unchanged
(CLI-only, Linux-only, Local Index, central versioned dataset; search
never triggers discovery).

### Fixed

- `gseer source add --seeds` now accepts comma- OR whitespace-separated
  seed lists (`normalizeSeedArgs`).  Found by the Rev 11 workflow
  dry-run: the pipeline passes `shlex.join` output (space-separated) as
  a single argument and pflag's StringSliceVar only splits commas, so
  the DNS connector received ONE nonsense "domain".  Regression tests
  added (internal/cli/source_test.go).

### Changed

- Seed register expanded to 14 DNS-only seed domains with a documented
  per-host terms basis; ACTIVE TLS :443 observation is now restricted to
  an explicit `tls_hosts` subset (10 hosts), each justified in the
  register header — passive DNS seeds are never probed.  The workflow's
  seed parser emits SEED_TLS_HOSTS, validates that tls_hosts is a subset
  of domains, and the scan step iterates only the terms-cleared hosts.

### Evidence (Rev 11 acceptance)

- Dataset v104: 156 REAL records (central-dns 109, central-ptr 11,
  scan-tls 36), 138 assets, 18 service-bearing records — built,
  validated, and reconciled 5/5 against the staging store.
- Clean-install journey over a production-fidelity HTTPS channel (GitHub
  release path layout, test CA injected via SSL_CERT_FILE): setup
  auto-imports v104, `search "port=443"` returns 12 REAL results,
  domain/hostname searches work, provenance + freshness reported,
  offline search identical with the channel dead.  TLS verification is
  PROVEN enforced (without the CA the handshake fails: x509 unknown
  authority) and a tampered payload is refused (E_DATASET_CHECKSUM,
  database untouched).
- Real internet: the official channel URL answers HTTP 404 today — the
  CLI reports it honestly (exit 4) and documents that the owner runs the
  pipeline; a real GitHub release asset is followed through GitHub's CDN
  redirect and then honestly rejected as non-dataset content.
- Production publication itself requires the owner's git write (push the
  included workflow) — explicitly NOT claimed here.

## [Unreleased] — Rev 10: targeted remediation of the Rev 9 acceptance (owner directive)

No architecture, product, or scope changes — Rev 9's accepted results stand.

### Fixed / hardened

- Recovery-forced acceptance failure (RECOVERY_EXIT=127) root-caused to the TEST
  HARNESS (shell composition backgrounded the binary-path assignment — bash ran a
  bare `dataset` command word → 127), NOT the implementation; evidence recorded in
  the incident analysis, the accidental HOME artifact cleaned up, and the test
  re-run with a correct harness: recovery restores the snapshot, removes an
  orphan half-import row, dedupes, exits 0.
- docs/DATASET.md: "Row-count semantics" section — rows.services counts
  SERVICE-BEARING RECORDS (one TLS scan = two records: asset-level + service);
  imported service rows collapse onto the (asset, port, transport) identity, so
  the index may hold fewer service rows than rows.services (6 records → 5 rows
  for example.org apex+www sharing one IP).
- Workflow hardening: post-publish round-trip verification (download the released
  assets back, re-validate, byte-`cmp` against the validated artifacts — an
  invalid/silently-corrupted asset now fails the job) and `if: always()` on the
  per-run audit artifact (evidence preserved on publish failure).
- New tests pinning the PRODUCTION channel contract:
  TestOfficialChannelMatchesGitHubReleaseLayout (the default URL matches the
  GitHub release layout: tag `central-dataset` + the two stable asset names;
  payload resolution stays inside that layout) and
  TestReleaseLayoutChannelServesTheJourney (a release-path-shaped loopback
  fixture serves the full journey: manifest → payload → atomic import → port=443
  row).

## [Unreleased] — Central Internet Asset Dataset pipeline (Rev 9, owner mandate)

The central dataset distribution is now a FIRST-CLASS product channel:
the project's scheduled GitHub Actions pipeline collects passive
discovery evidence over the terms-reviewed connectors, validates it, and
publishes a versioned, checksummed artifact that every fresh install
downloads, verifies, and imports atomically.  The Rev 8 architecture
decisions stand unchanged: CLI-only, Linux-only, no dashboard/website/API
server, no shared-index query service — the dataset only FEEDS the Local
Index, and search stays local (never triggers discovery or scanning).

### Added

- `internal/dataset` — the dataset channel: manifest (version, payload
  checksum + record counts, per-source provenance, observed_at bounds,
  freshness metadata), capped/timeout-bounded https fetcher (http only
  on loopback), and the ATOMIC import (pre-import 0600 snapshot via
  VACUUM INTO → stream through the standard ingestion path — suppression
  gate, delivery-identity dedupe, provenance preserved → count
  verification → rollback on ANY failure → interrupted-import recovery
  with stale `-wal`/`-shm` sidecar removal → install-state recording).
- `cmd/gseer-dataset` — the maintainer-side builder/validator: exports
  the staging Local Index as the dataset payload + manifest (fixture
  rows and import bookkeeping excluded; every record validated — one
  invalid record fails the build) and re-verifies published artifacts
  (checksum + count + per-record validation; the publication gate).
- `gseer dataset update|check|status` — the CLI channel: update downloads
  the manifest, verifies the payload checksum, and imports atomically
  (version gate; `--force` re-imports; `--manifest-url` override);
  `gseer setup` auto-imports after the local bootstrap (an unreachable
  channel degrades to an honest `[warn]` — setup still exits 0).
- `dataset.manifest_url` config section + `GSEER_DATASET_MANIFEST_URL`
  env (https always; plain http only for loopback hosts).
- `.github/workflows/dataset.yml` + `pipeline/dataset-seeds.yaml` — the
  scheduled pipeline (staging index → seed-register collection → scoped
  TLS :443 observation → build + validate → rolling `central-dataset`
  release publication).
- `docs/DATASET.md` — the channel contract.

### Tests (new, all passing)

- manifest schema/validation matrix; URL transport rule; fetcher
  checksum-mismatch + unreachable; import happy path + idempotency
  (same-version re-import dedupes), bad-record rollback (database
  byte-state preserved), interrupted-import recovery (orphan rows
  removed); CLI update happy path (search finds the imported rows),
  checksum failure leaves the DB untouched, unreachable honesty, setup
  auto-import journey (setup → import → `search port=443` returns the
  dataset row).

## [Unreleased] — CLI-only / Linux-only architecture remediation (owner architecture decision)

Owner architecture decision implemented: **GSEER is a Linux-only,
CLI-only, fully self-hosted product** with NO shared-index dependency.
Every change below is a removal of a non-product surface or the
replacement of the removed data path with a local one; no FIX5/FIX7
security boundary was weakened.

### Removed — shared-index (was the mandatory data source)

- `internal/index/` (the signed shared-index client: ed25519 trust
  anchor, signed manifest, fetcher, snapshot install/update, export),
  `cmd/gseer-provider/` (snapshot builder/publisher), the `gseer index`
  command, the `setup` shared-index step, the `index.*` config section
  (`GSEER_INDEX_MANIFEST_URL`), the `INDEX_PUB_B64` release key
  ceremony, and `.github/workflows/index.yml` (the publisher pipeline).
- The architecture now runs WITHOUT any shared index: `gseer setup`
  bootstraps LOCAL passive discovery instead (see Added).

### Removed — API server, dashboard, client profile (CLI-only)

- `internal/api/` (REST API), `internal/dashboard/` (dashboard UI), the
  `gseer server` command (start/stop/status daemon with PID
  management), the `client` profile and `client.*`/`server.*` config
  sections (`GSEER_CLIENT_ENDPOINT`, `GSEER_LISTEN`, `GSEER_TOKEN`,
  `GSEER_SERVER_TRUSTED_PROXIES`), and the `go-chi/chi` dependency.
- The compose "full stack" template no longer runs a server container:
  `--full` = db + one-shot hardened `provision` container; the
  Dockerfile default is `gseer --help`.

### Removed — platform and compatibility code

- Windows and macOS are no longer product platforms: the CI
  `update-windows` job, the GoReleaser darwin/windows targets, and the
  Windows release packaging are gone.  `.goreleaser.yaml` builds Linux
  amd64 + arm64 only.
- Windows-only code removed after dependency mapping:
  `restorefs_windows.go`, `update/dirsync_windows.go`,
  `apply_windows_test.go`, `personal_restore_windows_test.go`,
  `filename_windows_test.go`, the Windows branches in the updater and
  restore permission assertions, and the `USERPROFILE`/`gseer.exe`
  test shims.  POSIX behavior is unchanged.

### Added — local passive discovery bootstrap (the journey)

- `gseer setup` (fresh machine) now bootstraps discovery from the
  operator's egress context: public-IP echo (provenance `egress-echo`,
  `docs/SOURCES.md` §F) → PTR → registrable domain → bounded collect
  passes over the terms-approved connectors (`ptr`, `dns`, `ip2asn`)
  into the Local Index → at most 3 TLS `:443` handshakes under an
  auto-created, audited, revocable `domain_suffix` scope.
- `gseer search "port=443"` therefore returns REAL, verifiable evidence
  right after `gseer setup`; search itself never triggers discovery or
  scanning (unchanged Search ≠ Scan contract).
- `gseer status` and `gseer doctor` report LOCAL discovery freshness
  (registered sources + last successful collection run) in place of
  the shared-index block.

### Changed

- The default profile (no config anywhere) is `personal`; the two
  profiles are `personal` and `self-hosted` (headless CLI over
  PostgreSQL — the hardened deployment order, credential separation,
  and fail-closed privilege audit are unchanged).
- `gseer setup` self-hosted tails and `docs/QUICKSTART.md` /
  `docs/INSTALL.md` / `README.md` rewritten for the CLI-only,
  Linux-only product; `docs/SHARED-INDEX.md` deleted.

## [Unreleased] — Final remediation round (implementation complete; release pending)

Final remediation mandate on the `GSEER-v032-GLM-BASELINE-20261115`
integration baseline.  Every change is additive or fail-closed-strengthening;
no FIX5/FIX7 feature, security boundary, exit-code meaning, or public
compatibility was altered.

### Fixed

- **The shared-index pipeline is now genuinely fail-closed and atomic**
  (`.github/workflows/index.yml` + new `pipeline/resolve-sequence.sh` +
  `pipeline/publish.sh`): a genuinely nonexistent release is distinguished
  from an existing-but-inaccessible one (release view AND the releases API
  must agree before a sequence-1 bootstrap; an unreachable API is fatal, so
  the sequence is never silently reset to 1); a release whose manifest cannot
  be retrieved fails the run; signature, checksum, sequence, schema,
  integrity, and counts are all verified before a previous snapshot is
  restored as the working store; publication is ATOMIC (immutable snapshot →
  retrieval + checksum verification → anti-rollback/concurrency gate on the
  current pointer → pointer manifest last → independent post-publication
  verification) — a failed snapshot upload never advances the pointer.
  `force_fresh` remains an explicit owner-dispatched input, never an
  automatic fallback.  Negative + positive matrix proven by
  `scripts/v032-sequence-acceptance.sh` (stub-gh, offline, 12 assertions).
- **Production trust-anchor consistency**: both the shared-index workflow and
  the release workflow now VALIDATE `INDEX_PUB_B64` and ASSERT the production
  anchor is embedded in every built binary (release candidates included) —
  the in-repo test anchor can never silently become the production trust
  root.  Proven by `scripts/v032-anchor-acceptance.sh` (exact GoReleaser
  ldflags, both binaries, test-key rejection).

### Added

- **Cumulative shared-index pipeline** (docs/SHARED-INDEX.md §3): each
  sequence RESTORES the previously published snapshot as its working store
  after full trust verification — sequence N carries every fact of sequence
  N-1, so a fresh client's first import sees the whole accumulated coverage.
  Verified by `scripts/v032-cumulative-acceptance.sh` with real internet data
  (sequence persistence, client dedup, tampered/foreign-key refusals).
- **`gseer-provider inspect`** — the restore-time snapshot gate: SQLite
  `integrity_check` + schema position (never NEWER than this build —
  `InspectSnapshot` now refuses schema-ahead bases, mirroring the client's
  `ValidateSnapshot`) with an optional consistency cross-check against the
  signed manifest (sequence ≥ 1, schema and counts must match).
- **`app` as a GQL alias of `product`** (`app="nginx"` — FOFA/Shodan-style
  field naming; additive registry change, documented in
  `docs/SEARCH-SYNTAX.md`).

### Changed

- **CLI-only product contract in the official documentation** (README,
  QUICKSTART, INSTALL, DOCKER): the official product path is the CLI
  (INSTALL → SETUP → USE → SEARCH) with the autonomous GitHub Shared Index
  as the data source; the self-hosted PostgreSQL/Docker stack and the
  REST/dashboard surface are re-labeled as maintained developer internals —
  NOT official installation or usage paths.  No legacy code was removed:
  `internal/api`, `internal/dashboard`, and the PostgreSQL engine are
  load-bearing for CLI commands, tests, and migrations.

## [v0.3.2] — Real Internet Asset Data: Active Observation (implementation complete; release pending)

The v0.3.2 objective — real internet asset data — lands on two legs:
the passive pipeline (shipped, and verified against live DNS/ASN
sources — the independent live check of the `ptr` connector was
inconclusive because the verification environment's resolver did not
respond, so no live-PTR claim is made) is now completed by the
AUTHORIZED ACTIVE OBSERVATION regime.

### Added

- **`gseer scope` — the operator's authorization registry** (default-deny
  for active observation).  `scope add <kind> <value> --protocols
  http,tls --ports 80,443` records an explicit, operator-declared scope
  (the `--note` is where the authorization basis lives); `scope list`
  keeps revoked/expired history visible; `scope revoke <id>` takes
  effect on the next connection; `scope audit` shows every gateway
  decision.  A scope permits ONLY what it lists — empty protocol/port
  lists are refused at creation.  Private/loopback addresses are
  reachable only with a scope that explicitly covers the address or
  range.
- **Default-deny authorization gateway** (`internal/observe`).  Every
  connection — first request, every redirect hop, every reconnect —
  re-validates against the registry: missing/revoked/expired/mismatched
  scope ⇒ `E_SCOPE_DENIED` (exit 5), audited, and NO probe fires.  DNS
  rebinding protection: the gateway resolves once, validates every
  address, and observers dial only the validated address.  The residual
  pre-dial window is documented in docs/SCANNING.md, not overstated.
- **Two separate observers.**  `gseer scan http` performs ONE HTTP GET
  (status/title/server, response capped by the scope's byte budget);
  `gseer scan tls` performs ONE TLS handshake (version, cipher,
  certificate captured — capture, not verification).  Redirects
  re-enter the gateway hop by hop; `https://` redirects are recorded,
  not followed.  Both record honestly: a connection failure is an
  observation of failure, never "asset absent".
- **Migration `0018_active_observation` (PostgreSQL)** — the deferred
  `scopes` table extended in place (protocols, ports, expiry,
  revocation, execution limits) + the append-only `scan_audits` +
  additive `gseer_app` table grants (no sequence grants: the fail-closed
  privilege audit treats those as least-privilege violations).
- **Migration `0002_active_observation` (personal SQLite)** — personal
  mode gains the FULL scope registry + audit log (parity with PG).
- **`docs/SCANNING.md`** — the operating manual for the regime.
- **The shared index (approved v0.3.2 scope) — the search-engine
  half of the product.**  `internal/index` implements the full trust
  chain (Ed25519-signed manifest → sequence gate → SHA-256 →
  integrity/schema/count validation → atomic install with one-
  generation rollback → L1/L2-dedup import with provenance
  `shared-index`); `cmd/gseer-provider` (keygen/build/manifest/verify)
  and the scheduled `.github/workflows/index.yml` build and publish
  the versioned snapshot to the rolling `shared-index` release
  (immutable per-sequence artifact + atomic pointer manifest;
  `--latest=false`).  `docs/SHARED-INDEX.md` is the manual.
- **`gseer setup` is now the Easy-to-Use default (v0.3.2).**  On a
  fresh machine it provisions personal mode AND downloads the official
  signed shared index — after it, `gseer search 'nginx'` returns real
  indexed internet assets.  `gseer setup --server <url>` implements
  the client-profile wizard (persists `client.endpoint` + health
  check); configuration failures exit 3 (`ExitConfig`); the
  self-hosted validator refuses a non-`postgres://` DSN (the mirror of
  the personal guard — the audited SQLite-path-as-PG-DSN bug).
- **`gseer index update|status`** — the client lifecycle command
  (freshness check, full update, status); `gseer doctor` and the bare
  `gseer` status panel surface index freshness.
- **Certificate breadth + IP-aggregation aliases (approved scope).**
  Migrations `0021_cert_projection` (PG) / `0005_cert_projection`
  (personal SQLite) project the TLS observer's `cert_serial` and
  `cert_sans_dns` into `latest_tls` → `search_index`; new searchable
  fields `cert.sn` and `cert.domain`, plus the compat aliases
  `ip_country/ip_region/ip_city/ip_after/ip_before`.  The aggregate
  functions (`ip_filter()`, `ip_exclude()`, `port_size*`) remain
  intentionally unsupported (docs/SEARCH-SYNTAX.md).
- **Scan-path fingerprint enrichment (wiring fix).**  `gseer scan`
  now attaches the same rule engine the collect path uses, so
  scan-http/tls evidence is fingerprint-enriched at ingestion and
  `technologies` is searchable right after a scan.
- **Bare-keyword grammar completion.**  An unquoted bare word that is
  not a known field is free text (`gseer search 'nginx'`); known
  fields keep the `exists` semantics and dotted typos still fail with
  `GQL_E_FIELD`.  Both search services now compile the VALIDATOR'S
  rewritten tree (the pre-expansion tree was silently compiled
  before — free-text/bare-keyword expansions were dropped).

### Changed

- `gseer scan` is no longer a coming-later stub (it was a hidden exit-64
  pointer): it is a real command behind the gateway.  `gseer asset`
  remains the one planned-but-absent command.
- The root help now shows the authorized-observation quick start; the
  Search ≠ Scan invariant is untouched (search still imports nothing
  from the observation path).

### Security (final independent-review remediation — lease identity & domain-aware revalidation)

- **Pre-dial re-validation is now domain-aware (Blocker A).**  The
  earlier `Gateway.Revalidate` rebuilt its decision from the pinned IP
  alone, silently re-writing `domain`/`domain_suffix` scopes into
  address matching: validly-scoped hostname targets were denied at the
  pre-dial gate, and hostname permissions were no longer re-tested at
  all.  Re-validation now carries the ORIGINAL normalized hostname
  alongside the pinned address — domain/suffix scopes keep matching by
  name (exact label boundaries: `example.com.attacker.test` is never
  `example.com`), `ip`/`cidr` scopes and the restricted-address policy
  keep matching by the address that will actually be dialed, and
  protocol/port/expiry/revocation are re-checked against the CURRENT
  registry.  No DNS resolution happens inside re-validation: the pin
  stands, rebinding protection is unchanged, and a bare IP target is
  never covered by a domain scope.  Covered by a gateway-level matrix
  (no dial, TEST-NET-3 decision targets) plus loopback end-to-end runs
  for both observers.
- **Leases now carry per-acquisition ownership tokens (Blocker B,
  part 1).**  The 0019/0003 holder identity (`hostname#pid`) was shared
  by every observation in one process, and release matched
  (scope, slot, holder): a late-finishing observation could DELETE a
  newer observation's lease on the same slot, silently opening a
  concurrency slot that was still in use.  Each acquisition now owns a
  128-bit crypto/rand token (additive migrations 0020 PostgreSQL /
  0004 SQLite); release matches (scope, slot, token), so an old
  holder's late release is a no-op against a newer holder's lease, and
  double release is safe.
- **Leases are renewed while the observation is live (Blocker B,
  part 2).**  A TTL without renewal let an ACTIVE observation's lease
  be stolen mid-run.  A renewal heartbeat now extends the lease every
  TTL/3 (~40 s for the 2-minute TTL), token-verified and never
  resurrecting a stolen or lapsed lease (`storage.ErrLeaseLost`).  A
  renewal failure — lease lost or lease-storage error — is fatal for
  the observation: no NEW connection is opened (HTTP loop gate, HTTP
  dial gate, TLS pre-dial gate), in-flight work completes and is
  recorded honestly, and the heartbeat goroutine never outlives its
  run (Stop is idempotent and waits).  Crash recovery via TTL is
  unchanged; the concurrency limit remains per-scope across processes
  (SQLite and PostgreSQL in lock-step), never claimed as a global
  quota.

### Security (independent-review remediation — v0.3.2 microfix)

- **Audit persistence fails closed (FIX A).**  The gateway previously
  recorded an `audit_error` detail but returned the allow anyway; an
  authorization whose audit row cannot be persisted is now an explicit
  `AUDIT_UNAVAILABLE` deny — no HTTP request or TLS connection may run
  unaudited.  Denies keep their original reason and surface the audit
  failure; a failed insert writes no row, so no duplicate audit rows
  appear; the registry-unavailable deny is now audited too (that path
  previously skipped the trail).
- **Authorization is re-validated before EVERY connection (FIX B).**
  The first hop previously reused the initial decision: a scope
  revoked between `Authorize` and the first dial was not enforced
  until a redirect.  Now the first hop re-authorizes immediately
  before its request, every redirect hop revalidates its new
  destination, and every dial — first, retry, reconnect — passes
  `Gateway.Revalidate` (pinned address vs the CURRENT registry,
  audited) immediately before the socket connect.  Revoked, expired,
  missing or out-of-scope targets deny with nothing sent; rebinding
  protection and the pinned address are unchanged.  The residual
  registry-read→connect window is documented (docs/SCANNING.md), never
  overstated.
- **`max_total_bytes` is an ACCUMULATED run budget (FIX C).**  It was
  reused as a fresh per-hop limit, letting N redirect hops consume N ×
  budget.  The counter now spans the whole run — the metric is bytes
  actually read from response bodies (headers excluded; the one-byte
  truncation probe counts because it is read), never reset on a
  redirect, subtraction clamped so it cannot underflow.  Mid-body read
  errors are recorded as failures (previously silently swallowed);
  exhaustion is recorded (`truncated` / recorded-not-sent), never a
  silent complete response; the accumulated count lands in the
  persisted evidence (`scan.response_bytes`).
- **`max_concurrency` is now actually enforced, cross-process
  (FIX D).**  The knob existed with no enforcement anywhere.  A run
  must hold one of the scope's `scan_leases` slots (1..N) for its
  whole duration — new additive migrations 0019 (PostgreSQL) / 0003
  (SQLite), identical protocol on both engines: slots are stolen only
  when their TTL (2 min) has passed (crash-safe, no unlimited stale
  locks), releases are holder-scoped, and busy or any lease-storage
  failure fails closed with no probe (`E_SCOPE_BUSY`, exit 1, is the
  busy answer — not a denial).
- **Documentation now matches the enforcement (FIX E).**  The 0018
  wording ("per-run connection concurrency") described a knob nothing
  used; the authoritative semantics — accumulated response-body bytes
  across hops, scope-level simultaneous observations across processes —
  are documented in docs/SCANNING.md, the CLI help, and (PostgreSQL)
  `COMMENT ON COLUMN` corrections in 0019.  Historical migrations are
  untouched.

## [v0.3.1] — Install Path & First-Run Correctness

Real-world acceptance testing found two correctness failures that CI
could not see: the documented install command failed outright, and the
first engine command on a fresh machine dead-ended in an unrelated
configuration error.  Both are fixed; no check was weakened and no
behavior was faked.

### Fixed

- **Windows CI: the restore's staging cleanup and the module-path guard are now Windows-correct.**  Two real windows-latest CI
  failures, both invisible on POSIX: (1) on the injected
  close-failure path, `copyFile` removed the partial staging file
  while its handle was still open — Windows refuses to delete an
  open file (sharing violation), so a leftover
  `gseer.db.restore-staging` survived every simulated close failure
  and even broke the test framework's temp-directory cleanup.  The
  cleanup now releases the REAL handle first (deliberately not the
  test seam whose injected failure is exactly what cleanup must
  survive), removes the file only afterwards, and reports a removal
  that still fails next to the primary error instead of silently
  discarding it.  (2) the install-path guard compared go.mod's first
  line byte-for-byte; a Windows `git clone` (core.autocrlf) ends
  every text line with CR, so the guard rejected the CORRECT
  declaration while printing two identical-looking lines.  Only the
  CR artifact is stripped now — a BOM, wrong case, or any other
  deviation still fails the guard (verified: the stale UPPERCASE
  declaration is still caught under CRLF).  Both behaviors are
  pinned by tests that were reproduced and re-run on a real
  Windows runtime (windows/amd64 test binaries executing the
  windows test suite), not by cross-compilation alone.
- **The exact documented install command now matches the module.**
  `go.mod` declared the module path with an UPPERCASE repo segment
  (`…/GSEER`) while every README/INSTALL/QUICKSTART command teaches the
  lowercase form — and Go module paths are case-sensitive, so
  `go install -v github.com/Lutfifakee-Project/gseer/cmd/gseer@latest`
  failed with "module declares its path as … but was required as …".
  The module declaration, all imports, the ldflags `-X` injections
  (Makefile, Dockerfile, `.goreleaser.yaml`), and the doc URLs now use
  the one lowercase path.  Verified with a clean-environment proxy
  fetch of the fixed module (the negative control on the v0.3.0
  artifact reproduces the reported error byte-for-byte).
  Transitional reality (verified this cycle): the documented `@latest`
  form still errors until the v0.3.1 tag is published, because tag
  resolution picks the v0.3.0 tag — its `go.mod` is the UPPERCASE path
  this release fixes; `@main` installs cleanly from the proxy today
  (honest "unknown" VCS fields), and `@latest` resolves v0.3.1 by the
  same rule once it is the latest tag.
  (Status note, added 2026-11-14: v0.3.1 is now the latest published
  tag — the Go module proxy serves v0.3.1 and the documented `@latest`
  install resolves it.  The paragraph above records the transitional
  state during the release cycle only.)
- **Zero-configuration first run covers every engine command.**  With
  no configuration anywhere, the first `gseer search`, `gseer source
  add`, `gseer collect`, `gseer suppress`, `gseer export`, or
  `gseer db backup` failed with `E_CONFIG_REQUIRED: client.endpoint` —
  presented to users exactly like "source/collect are rejected in
  personal mode".  Engine commands now run the SAME personal-mode
  initialization bare `gseer` uses (one code path, no drift) when
  nothing is configured; an explicit `--profile`/env choice is never
  overridden.  `search --validate`/`--explain` need no configuration
  and provision nothing.  `doctor` on a fresh home reports the
  zero-config state as a PASS note instead of a failing config check
  (still strictly read-only).
- **Stale version anchors removed from user-facing error surfaces.**
  On a v0.3.1 binary, `gseer scan`/`gseer asset` still printed
  "planned, not in this release (v0.1.0)", the reserved
  `search --collapse` help and pointer line said "PLANNED for v0.1.0",
  and the GQL planner/validator refusal explanations still said
  "v0.0.1 ships …" / "v0.0.1 quantifies …".  All now describe the
  running product without a wrong release stamp; messages, exit codes,
  and refusal semantics are otherwise unchanged (text-only).

### Added

- **The operator's DNS seed is a first-class searchable domain asset.**
  Collecting `--seeds example.com` now records `example.com` itself as
  a `domain` asset (confidence `high`, evidence marked
  `seed: {mode: …}`), so `gseer search 'asset_value=="example.com"'`
  finds it and the seed ↔ resolved IP ↔ CNAME/MX/NS relationships stay
  queryable through the shared canonical query name and the source's
  provenance.  Honesty contract kept: the seed fact asserts only that
  the connector TARGETED the name — it carries no DNS record type and
  never claims a record answer the resolver did not return; it is
  counted neither as an answer nor as an error, so the
  all-lookups-failed retry sentinel behaves exactly as before.  Asset
  identity stays `(kind="domain", value)` after canonicalization, so
  re-collecting the same seed from several sources merges into ONE
  asset with unioned source provenance instead of duplicates.
- Regression tests driving the real binary through first-command
  flows (`source add`/`search`/`suppress list`/`doctor`) and module
  path guards that keep `go.mod`, the imports, and the docs on the
  lowercase public path forever.
- DNS/ip2asn regression hardening: nil and empty `net.MX`/`net.NS`
  answer entries, whitespace-only and malformed hostnames, and
  trailing-root-dot normalization are now pinned by tests; multi-line
  IP-to-ASN origin answers (first line wins) and registry-only AS-name
  answers (stored organisation stays EMPTY — never the registry field)
  are pinned at the connector level.
- **Harden `db restore` into an explicitly recoverable replacement.**
  The personal-mode restore no longer opens the live database's
  destination with a truncating copy and no longer discards a previous
  recovery file.  The backup is first staged in a fresh exclusive
  temporary file inside the live database's own directory, fsynced,
  closed with its error checked, forced to `0600` after the umask, and
  validated with a real SQLite open plus `PRAGMA quick_check` — only
  then is the live database (together with its `-wal`/`-shm` sidecars,
  so a stale WAL can never be crash-recovered against the new file)
  moved aside to `gseer.db.restore-old` and the staged copy renamed
  onto the live path (POSIX: same-directory `rename(2)`; Windows:
  `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH`,
  never a cross-volume copy).  Every completed rename is rolled back in
  reverse order on failure, a rollback that itself fails is reported
  explicitly with the location of every artifact, and a previous
  `.restore-old` is archived to a timestamped name — never silently
  deleted.  User-facing text says "recoverable replacement", never
  "atomic", because the two-rename swap is exactly that: recoverable.
  Pinned by a deterministic failure-injection battery (staging copy /
  sync / close / replacement / rollback failures, invalid and
  truncated backups, missing backup, self-restore refusal, recovery
  file preservation, cross-directory restores, first-run missing live
  file) through I/O seams — no permission tricks that misbehave under
  root — plus Windows-specific tests for the replacement primitive.
- **The v0.3.1 acceptance battery is now tracked in the repository**
  (`scripts/v031-acceptance.sh`): drives the real compiled binary in an
  isolated temporary home (never the operator's data), fails fast with
  explicit `[PASS]`/`[FAIL]` lines, counts only independently executed
  assertions, and now also covers restore-failure recovery (invalid
  and missing backups refused, live database intact, recovery file
  preserved and archived, no staging leftovers).  Synthetic fixture
  checks and live-DNS checks are labeled separately.
- Docs corrected: `git clone` now says the real directory name
  (`gseer`, not `GSEER` — the old form fails on case-sensitive
  filesystems), build examples pin v0.3.1; `docs/SOURCES.md` §C and
  `docs/QUICKSTART.md` document the seed asset, the `seed-mode`
  (`config` = explicit operator seeds, `index` = seeds drawn from the
  existing asset index) and the `seed-kind` scope (it selects the asset
  kind index seeds are drawn from — it does NOT re-classify the seeds
  themselves); `docs/QUICKSTART.md` now documents exactly what
  `db restore` guarantees, where the previous database is preserved,
  and how the operator recovers from a failed or wrong-file restore.
- Docs re-synced to v0.3.1 (the earlier "stale stamps updated" sweep
  had missed two files): `docs/DEPLOYMENT.md`'s evidence classes now
  cite the v0.3.1 binary — hardened order, doctor `6 PASS`, startup
  gates exit 3/5/5, exit-code table 0/1/2/3/5/64 reproduced live on
  PostgreSQL 16.15 this cycle — instead of the v0.2.0 round, and the
  exit-code table gains the honest generic exit-1 row;
  `docs/UPDATE.md` manifest examples use the current version, the
  channel note is present-tense, and its section numbering is
  contiguous (§6, not a jump to §8); `README.md`'s troubleshooting now
  separates the client-profile `E_CLIENT_ONLY` refusal from personal
  mode's `E_PROFILE_UNSUPPORTED` on `gseer host` (self-hosted-only in
  this release — the old row implied host works in personal mode); the
  QUICKSTART first-run sample now shows the real four-line output; and
  `docs/INSTALL.md` + `README.md` document the transitional `@latest`
  state (tag resolution picks v0.3.0's UPPERCASE `go.mod` until the
  v0.3.1 tag exists; `@main` verified as the interim install).

### Verified (release evidence)

- Linux: full suite green (`go test -count=1 ./...`), `-race` clean,
  `go vet` clean, `golangci-lint` 0 issues, `govulncheck` clean.
- PostgreSQL 16 fail-hard battery green.
- The tracked acceptance battery green against the real binary in an
  isolated home (49/49 assertions).
- Windows: the two CI failures are fixed and the full
  `go test -count=1 ./...` suite passes on windows-latest — first green
  on the fix commit (CI run 43153349926), re-confirmed on the
  release-content commit by GitHub Actions run #32
  (https://github.com/Lutfifakee-Project/gseer/actions/runs/43163565189)
  and on the metadata parent of this candidate by run #33
  (https://github.com/Lutfifakee-Project/gseer/actions/runs/43184608744)
  — all ten jobs green in both (Go 1.26.x/1.27.x build & test, the
  windows full-suite job, lint, govulncheck, the goreleaser
  release-config check, Search ≠ Scan, and the PostgreSQL 16/17
  integrations).  The pending-release commits after run #33 change
  only docs and error-message text; the final tree is covered by the
  local battery in the other bullets of this list.
- Cross-compilation of all release targets succeeds.

## [v0.3.0] — Zero-Config First Run, Personal Collection, New Identity

Positioning rename: GSEER is the **internet-asset search engine** (the
former intelligence-platform tagline is retired everywhere — README,
CLI, dashboard, docs).  The data-source register
(`docs/SOURCES.md`) remains the one place external data providers are
named, because data provenance must be transparent.

### Added

- **Zero-configuration first run.**  Bare `gseer` now initializes
  personal mode automatically when no config exists (same permission
  policy, migrations, and config writer as `gseer setup --personal` —
  one code path, no drift), then tells the user exactly how data
  enters the index.  A later bare run prints an honest status panel
  (profile, database, index counts, the next useful commands).
- **`--version` finally works.**  The root flag existed since M1 but
  was never consumed; bare `gseer --version` now prints the version
  block.
- **Collection works in personal mode.**  The collector engine now
  runs against the storage `Backend` contract instead of the concrete
  PostgreSQL store: `gseer source add/list/enable/disable`,
  `gseer collect run/status/redrive`, and fingerprint enrichment all
  work against the personal SQLite file.  The client profile is
  still refused honestly (`E_CLIENT_ONLY`); the self-hosted PostgreSQL
  paths are behavior-identical.
- **New connector: `ptr` (reverse DNS).**  Resolves PTR records for
  operator-named addresses (seed mode config or index) through the
  operator's resolver and records hostname sightings with provenance.
  Reviewed-enabled on the same basis as the `dns` connector —
  standard protocol, operator-named targets, protocol facts
  (`docs/SOURCES.md` §E).  No CIDR sweeps, no neighbor enumeration.

### Changed

- **README rebuilt user-first**: what GSEER is → install → quick start
  → search examples → syntax → data collection → storage/backup →
  configuration → troubleshooting → uninstall.  The fastest path from
  `go install` to a first search is the top of the document.
- `gseer --help` and the dashboard now carry the new identity and the
  zero-config quick start.
- Canonical collection types (`DataSourceRow`, `DeadLetter`, the
  lookup-miss sentinel) moved to `internal/storage` so both engines
  satisfy one typed contract (compile-time pinned in the CLI).

### Fixed

- **Post-push CI gate restored (lint + Windows).**  The dns
  connector's `Collect` grew past the gocyclo budget (30 > 20) when
  MX/NS collection landed; it is decomposed into focused per-record
  helpers (`collectAddrs`/`collectCNAME`/`collectMX`/`collectNS` over
  one pass accumulator) with byte-identical behavior, and the first-run
  tests now isolate the home directory on every platform —
  `os.UserHomeDir()` reads `$HOME` on Unix but `%USERPROFILE%` on
  Windows, so the Windows runner initialized into its real profile and
  failed the artifact assertions.  New regression tests pin the
  invalid-seed dead-letter contract, the self-referential CNAME guard,
  and the MX preference evidence.
- **ip2asn stored the registry instead of the AS name.**  The
  `asn.cymru.com` AS-name answer is five pipe-separated fields
  (`AS | CC | registry | allocated | AS NAME`); the parser read field
  3, so the `asn_org` column got `arin`/`apnic` instead of e.g.
  `GOOGLE - Google LLC, US`.  Verified against the live service
  2026-11; regression tests pin the captured live-format lines.
- **dns connector coverage gap: MX and NS.**  The connector now also
  records MX and NS answers as hostname asset facts (same resolver,
  same terms basis); MX/NS lookups are best-effort per seed and their
  answer counts land in job stats.  TXT stays uncollected by design
  (no typed, searchable column — documented in SOURCES.md §C).
- `gseer collect status` no longer runs ad-hoc SQL in the CLI; it
  reads the same store contract the rest of the engine uses (and now
  works in personal mode).
- CLI collection commands resolve their context defensively
  (`commandContext`), so a mis-wired invocation can no longer hand a
  nil context to the database layer.

## [v0.2.2] — Personal-Mode Wire-Up Fixes

Found by the first real personal-mode walkthrough (`go install` →
`setup --personal` → daily commands).  No security boundary is
weakened; the PostgreSQL paths are untouched.

### Fixed

- **`go install` binaries report their real version.**  The version,
  commit, and built_at fields fall back to the toolchain's own build
  information (`debug.ReadBuildInfo`: module version, `vcs.revision`,
  `vcs.time`) when no `-ldflags` injection is present — so
  `go install .../cmd/gseer@v0.2.1` no longer prints
  "gseer dev / commit unknown".  Values are never fabricated: a plain
  development build keeps the honest "dev"/"unknown" reporting.
- **`gseer doctor` runs real personal-mode checks.**  A personal
  profile used to fall into the client branch ("DB checks: skipped
  (client profile has no local database)" + a server-endpoint hint).
  Doctor now checks the database file (existence first — it never
  creates one), the read-only SQLite migration state, and the same
  index-contents honesty contract (EMPTY / FIXTURE-labeled / counts).
- **`gseer setup --load-fixtures` / `--purge-fixtures` follow the saved
  personal profile.**  The standalone fixture actions tried to parse
  the SQLite database FILE as a `postgres://` DSN
  (`E_DB_UNREACHABLE: cannot parse …`).  They now ingest/purge through
  the personal store behind the same QS-6 gate; the load output no
  longer suggests `gseer server start`, which personal mode cannot run.
- **`gseer export` works in personal mode.**  The exporter now pages
  through any `Search` implementation (`export.Searcher`), so personal
  mode streams the same JSON / CSV / NDJSON via the embedded SQLite
  service.  The PostgreSQL path is byte-identical.
- **Honest refusals instead of PostgreSQL errors on the personal
  profile.**  `source` / `collect` (collection registry is
  PostgreSQL-only) and `host` (report runs through the PostgreSQL
  service) now refuse with `E_PROFILE_UNSUPPORTED` naming what is
  missing and what to do, instead of a misleading
  `E_DB_UNREACHABLE: cannot reach PostgreSQL`.
- **`setup --personal` next-steps hint fixed**: it suggested
  `gseer server start`, which refuses non-self-hosted profiles; the
  hint now points at the personal surfaces (search, fixtures,
  suppression, backup).

### Added

- Personal-mode test coverage: standalone fixture load/purge round
  trip, doctor personal checks (including the read-only no-create
  contract for a missing database file), the profile gates, and a
  personal NDJSON export through the CLI.

## [v0.2.1] — Compatibility Layer, Personal Mode, Release Engineering

Compatible increment over v0.2.0.  PostgreSQL stays the primary engine
for self-hosted server deployments; SQLite personal mode is additive
and profile-gated.  No security boundary is weakened.

### Added

- **GQL compatibility layer**: `*=` suffix-anchored fuzzy match, bare
  free text, `after`/`before` rewrites, derived booleans, empty-value
  semantics, quoted-integer coercion (`port="443"`), field aliases
  (`org`, `app`, `base_protocol`, `status_code`, `cert.subject.cn`),
  and the `host` alias matching hostname OR IP.  Grammar + examples in
  `docs/SEARCH-SYNTAX.md`.
- **Personal mode on SQLite** (`gseer setup --personal`,
  `GSEER_PROFILE=personal`): single-file DB (default
  `~/.gseer/gseer.db`) with the SQ-01…SQ-06 remediation set (upsert
  FirstSeen consistency, millisecond timestamps, DSN special-character
  safety, 0600/0700 file-permission policy, single-writer WAL +
  `busy_timeout`, deny-wins suppression race with audit rows and
  fail-closed expiry), a dedicated SQLite search planner with
  PostgreSQL-parity tests, and `gseer db backup` / `gseer db restore`.
- **Release engineering (REL-01/02/03)**: module-root `main` as a pure
  `cli.Execute` delegate so `go install .../cmd/gseer@v0.2.1` works,
  validated GoReleaser v2.20.0 configuration with a green snapshot
  matrix, pinned release workflow producing draft releases only, and a
  CI release-config validation job.

### Fixed

- Single-host `/32` CIDR text-equality and suffix-wildcard matching
  (`ip *= "*.10"`) via `host(inet)` instead of masked `ip::text`.
- Quoted integer literals (`port="443"`, `port IN (80,"443")`) coerce
  in place; non-numeric quoted values still fail with a typed error
  and hint.

### Docs

- Neutral engine references outside `docs/SOURCES.md` (brand policy);
  `.gitignore` safety net for personal-mode SQLite artifacts.
- Root layout tidied: release notes → `docs/releases/`, banner →
  `docs/assets/`; internal evidence docs (architecture-spec revisions,
  CI integration report) are local-only and no longer published.

## [v0.2.0] — Hardened Self-Hosted Readiness

The hardened deployment model owner-approved as OD-1…OD-7 (Revision
6.7.2) lands in the binary, with the release-quality verification round
(fresh installs, fresh-clone reproducibility, PostgreSQL 16.15 + 17.2
matrices, real-binary E2E).  No security boundary is weakened; the
least-privilege direction stays one-way.

### Added

- **Migration 0016 — suppression policy hardening (pinned, hash-enforced).**
  The `gseer_policy` enforcement layer: refusal-first guard (OD-3),
  SECURITY DEFINER policy functions, statement-level advisory lock
  (GSER/POL1 keys, OD-6), `fn_check_asset_suppression` v2 backstop.
  Versions 0007–0015 stay permanently reserved (OD-4).  The pinned
  Rev 6.7.2 artifacts are embedded byte-for-byte
  (`internal/storage/migrations/`, `deploy/sql/`) and their SHA-256
  hashes are enforced by the test suite (`artifacts_test.go`).
- **Migration 0017 — search safe-casts (GAP-1 mandate).**
  `gseer_safe_int` / `gseer_safe_timestamptz` helpers and rebuilt
  `latest_http` / `latest_tls` views: malformed evidence can no longer
  break search/facets/export/host (a malformed value yields an empty
  cell instead of a query failure).  Up/down round-trip equality is
  automated.
- **Hardened setup — the deployment order in one command.**
  `gseer setup --self-hosted` now runs bootstrap → migrate → runtime
  grants → privilege audit (steps 1–4 of the approved sequence, in that
  order because the 0016 guard requires the roles), provisions the
  `gseer_app` runtime password (generated, printed once; or
  deterministic via `--runtime-password-env`; rotate via
  `--reset-runtime-password`), and refuses the deployment with the
  complete failure list when the audit fails.
- **Runtime credential switch (M-B).** `database.runtime_dsn` /
  `GSEER_DB_RUNTIME_DSN`: the server serves traffic ONLY as the
  least-privilege `gseer_app` credential; CLI data-plane commands
  prefer it and print an explicit notice when falling back to the
  operator credential (never silently).  Suppression writes go through
  the 0016 policy functions in every path (direct DML is refused by the
  policy gate with `GSUP2`).
- **In-binary fail-closed privilege audit (M-C, OD-5).**
  `gseer server start` runs the embedded audit under `gseer_app`
  BEFORE the port binds: a missing grant, unsafe role attribute, or
  escalation path in the membership closure refuses startup with the
  full failure list (exit 5).  A runtime-credential identity check
  refuses to serve as anyone other than `gseer_app` (exit 5).  No
  bypass exists.  `gseer doctor` runs the same audit as a check.
- **`gseer host <ip|hostname|domain>`** — read-only host inspection:
  the asset row (kind/value/ASN/geo/sources/first-last seen), every
  service with its latest HTTP/TLS/fingerprint state, and the
  observation provenance breakdown; `-o json` for machines.
- **PostgreSQL 16+ minimum (OD-7).** Enforced by `gseer setup` and
  `gseer doctor` (`minimum 16`); the compose stack keeps
  `postgres:17-alpine`.
- **Docker full stack, hardened (EU-2).** The server container
  provisions itself (bootstrap → migrate → grants → audit) and serves
  under `gseer_app`; the generated `.env` carries a dedicated
  `GSEER_APP_PASSWORD`; no container ever serves as the operator.

### Fixed

- **Collected assets carry source provenance.** Passive collectors now
  stamp the source name onto the asset row (the fixture loader already
  did): the `sources` facet, search_index projections, and `gseer host`
  reflect collector data instead of an empty array (a documented v0.1.0
  limitation, now closed with a regression test).
- **Honest migration counters.** `migrations: N applied` counts FILES,
  not version numbers — under the reserved 0007–0015 range the v0.1.0 →
  v0.2.0 upgrade applies 2 files to head 17 (not "11 applied").
- **Test-suite hermeticity and order independence.**
  `TestSetupSelfHostedFreshMachineContract` no longer depends on the
  absence of a local PostgreSQL (machines running one — CI included —
  made it fail); `executeRoot` resets cobra's per-command help/version
  flags so the banner/help tests no longer poison the E2E tests below
  them (the same shared-state class closed for command flags earlier).
- Integration harnesses bootstrap the hardened roles before migrating,
  derive their per-test DSNs from `GSEER_TEST_PG_ADMIN` (the suite now
  runs unchanged against any instance — the PG16/PG17 matrix), and the
  v0.1.0 → v0.2.0 upgrade path is an automated test
  (`TestV010ToV020UpgradePath`).

### Documentation (this release)

- `docs/DEPLOYMENT.md` rewritten around the implemented model (the
  SPECIFIED→VERIFIED gap is closed): credential model, the automated
  hardened sequence, what the audit checks, refusal table with safe
  repairs, the no-bypass rationale, exit-code table (5 = security
  refusal), and the hash-pinned artifact register.
- `docs/QUICKSTART.md` rewritten as the complete verified v0.2.0
  workflow (build → compose → hardened setup → runtime credential →
  doctor → scope → collection → GQL search → `gseer host` → hardened
  server start → health → shutdown) with troubleshooting picks.
- README, INSTALL, `.env.example`, DOCKER, UPDATE, and ROADMAP aligned
  to the v0.2.0 behavior; every documented command executed against the
  real binary on PostgreSQL 16.15 and 17.2.

### Verified (release evidence)

- Unit suites: 19 packages green.  Integration suites (build tag
  `integration`): green on PostgreSQL 16.15 **and** 17.2 (fresh
  databases per test; the matrix covers setup, migration up/down,
  suppression policy paths, search/planner/facets, export, fixture
  round-trip, collect/redrive).
- Real-binary E2E on both majors: hardened setup → doctor (6 PASS,
  0 FAIL) → fixtures → search/facets/export → suppress add/re-add/
  list/remove → `gseer host` (table + JSON) → authorized DNS collection
  → server start (audit under `gseer_app`) → health → graceful stop.
- Negative security tests (real binary): revoked grant → startup
  refused exit 5 with the GSUPF failure; decoy `INSERT` grant on
  `public.suppressions` → caught twice (ACL walk + point check), exit 5;
  operator DSN in `runtime_dsn` → `E_RUNTIME_CREDENTIAL_MISMATCH`,
  exit 5.
- Reproducible build: two fresh-clone builds produce byte-identical
  binaries (`-trimpath`, same toolchain).

## [v0.1.0] — First Useful Self-Hosted (Phase 3)

Milestones M18–M24.  No breaking changes to the v0.0.2 surface.

### Added

- **Fingerprint rule engine** (`internal/fprule`, M18): versioned rule
  collection (22 seed rules across web-server / cms / language /
  framework / web-tech / service families) with provenance, evidence-
  based confidence tiers, mandatory false-positive regression tests,
  and a lint that rejects exploitation/credential-shaped signatures.
  Ingestion enrichment attaches derived `fingerprint.technologies` to
  observations whose http/tls/ssh evidence matches (source-provided
  fingerprints always win; fixture loads stay verbatim).  Contribution
  format + confidence contract: `docs/RULES.md`.
- **`gseer rules list` / `gseer rules validate [--dir]`** (M18): the
  real implementations (previously exit-64 stubs); validate lints AND
  runs every rule's regression tests (exit 0 clean / 2 problems).
- **Faceted search** (M19): `planner.CompileWhere` + `search.Facets` —
  port, protocol, technology, service, country, source, freshness
  aggregates over the same GQL filter and SearchService as search
  (service mode counts rows; asset mode counts distinct assets).
  Surfaces: `gseer search --facets [--facet …] [--max-values]`,
  `GET /api/v1/facets`, dashboard facet panel.
- **Search export** (M20): `internal/export` streams JSON / CSV /
  NDJSON through the SearchService's keyset cursor (stable page
  sequence, O(page) memory).  CLI `gseer export` (stdout streams carry
  status on stderr; safe filenames — `..`/control-char/overwrite
  refusal) and streaming `GET /api/v1/export` with a server-generated
  Content-Disposition.  RFC 4180 CSV escaping; no credentials ever in
  the stream (pinned by tests).
- **Signed update system** (M21): `internal/update` + `gseer update
  --check|--apply` — Ed25519 manifest verification against the key
  embedded in the binary (verification FIRST, download LAST), semver
  version gate (downgrades refused without `--force`; unparseable
  versions fail closed), exact GOOS/GOARCH artifact selection,
  SHA-256 + size verification, capped/redacting HTTP fetcher, atomic
  rename with `.bak` backup and unconditional rollback.  Maintainer
  tooling: `cmd/gseer-release` (keygen/sign/verify).  `docs/UPDATE.md`.
- **Full Docker stack** (M22): multi-stage non-root `Dockerfile`,
  `docker-compose.full.yml` (db + server, healthchecks via `/health`,
  `depends_on: service_healthy`, persistent volume, NO published DB
  port, host-loopback API binding, mandatory generated API token) and
  `gseer setup --with-compose --full` (writes the stack + `.env` with
  both secrets at 0600).  Lifecycle docs: `docs/DOCKER.md`.
- **Dead-letter re-drive** (M23): `gseer collect redrive
  [--source|--all|--discard]` — rebuilds preserved records through the
  same normalization pipeline (suppression still applies; failures bump
  attempts and stay pending; `--discard` is the operator's explicit
  judgment).
- **Backup/restore procedure** (M23): documented pg_dump/pg_restore
  workflow inside the compose stack (`docs/DOCKER.md` §4).
- Config: `fingerprints:` (disabled / rules_dir), `update:` (manifest_url)
  sections with `GSEER_FINGERPRINTS_*` / `GSEER_UPDATE_MANIFEST_URL` env
  overrides.

### Changed

- `gseer update` and `gseer export` are real commands (previously
  hidden exit-64 stubs); only `scan` and `asset` remain planned.
- `technologies` in `search_index` can now be populated by rule
  enrichment at ingestion (previously only source-provided
  fingerprint evidence).

### Fixed (pre-release corrections, before the v0.1.0 tag)

- **Security**: `github.com/go-chi/chi/v5` upgraded v5.2.1 → v5.5.0,
  clearing GO-2025-3770 / GHSA-vrw8-fxc6-2r93 (open redirect in
  `middleware.RedirectSlashes`) plus three further published chi
  advisories (GHSA-3fxj-6jh8-hvhx, GHSA-j6qf-3m9c-vwj3,
  GHSA-rqrp-8cg2-5958).  The API server never mounted any of the
  affected middleware (client-IP handling is owned by
  `internal/httpx`); `govulncheck ./...` now reports **zero**
  vulnerabilities.  `golang.org/x/net` upgraded v0.56.0 → v0.62.0 for
  the same reason.  A source-level regression test pins the API to the
  advisory-free chi middleware subset.
- **CI**: the lint job moved from `golangci-lint-action@v6` +
  `version: latest` (which resolved to a v1.64.x binary built with Go
  1.24 and could not process a Go 1.26 module) to
  `golangci/golangci-lint-action@v9.3.0` (node24) with golangci-lint
  pinned to **v2.15.0** (Go 1.26).  The existing v2 lint configuration
  is preserved; obsolete v0.0.1/M1 workflow comments were refreshed.
  The nightly full-DB battery is now genuinely nightly: a `schedule`
  trigger (`0 18 * * *` = 01:00 Asia/Jakarta) and a `workflow_dispatch`
  trigger were added — the job runs on schedule and on manual dispatch,
  never on ordinary pushes (the fast integration-test job still runs
  on every push).  The
  `update-windows` job runs the full unit suite, vet and build on
  windows-latest in addition to the updater suite and its race.
- **Lint**: the codebase is clean under golangci-lint v2.15.0 with the
  existing rule set (no rules weakened; the only new exclusion is a
  documented, narrowly-scoped G101 exemption for the compose generator's
  format-placeholder templates).  Dead code removed, unchecked errors
  made explicit, file/dir permission hardening (`update` target 0750,
  executable mode kept for replaced binaries), 63-bit masking for
  fnv-derived BIGINT bookkeeping ids, and eight complex functions
  refactored table-driven without behavior change (full unit + race +
  integration suites green before and after).
- **Updater durability** (`internal/update`): `copyFile` now returns
  only after the copy is written, chmod'd, fsynced AND closed — Close
  errors surface when nothing earlier failed and cleanup never masks
  the primary copy/sync error; the backup keeps the running binary's
  exact permission bits via an explicit chmod (umask-proof, also on
  re-backup over an old `.bak`), so a backup is only reported usable
  once it is fully durable.  A failed post-rename directory fsync is no
  longer silently ignored: it surfaces as the `E_UPDATE_DIRSYNC`
  warning (binary replaced, nothing rolled back, crash durability not
  guaranteed — `Apply` returns the result together with the warning,
  `IsDirSyncWarning` detects it, and `gseer update --apply` prints it
  without the false "left untouched" failure line).  Platform helpers:
  explicit open+fsync+close of the directory on POSIX; on Windows the
  replacement primitive itself is `MoveFileExW` with
  `MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH` — Go's `os.Rename`
  calls plain `MoveFileW` with NO flags (never write-through), so the
  updater performs the replace itself; `MOVEFILE_COPY_ALLOWED` is
  deliberately omitted so a cross-volume replace fails loudly instead
  of degrading into a non-atomic copy.  Regression tests cover copy success /
  copy failure / sync failure / close failure and their precedence,
  backup permission preservation, atomic replacement, no-temp-leftover
  cleanup, rollback (incl. failed-rollback reporting) and the
  dir-sync warning contract.  Every `*Error` now carries its wrapped
  cause (`Unwrap`) — `errors.Is` / `errors.As` walk the live chain
  (MoveFileExW error → `*os.LinkError` → `*Error`) instead of a
  flattened string.  Windows-specific coverage (flags passed to
  `MoveFileExW`, replace with/without an existing target, API errors,
  rollback, warning propagation, platform-honest permission semantics
  via `assertPerm`, leak-free injected-close stubs) runs on the
  `update-windows` CI job (windows-latest, Go 1.27.x).  Every
  permission assertion in the updater suite — `apply_test.go`,
  `apply_windows_test.go` and the full-chain `TestApplyFullChain` in
  `update_test.go` included — goes through `assertPerm`: exact POSIX
  bits on Unix, writable/read-only semantics only on Windows (no
  exact-mode claim is made there, and no assertion was weakened or
  removed).

## [v0.0.2] — Passive Intelligence (Phase 2)

Milestones M13–M17.

### Added

- **Suppression engine** (M13): `suppressions` + `suppression_applications`
  (migration 0005), the Go ingestion gate + DB backstop trigger
  (`GSUP1` → `E_DB_SUPPRESSED`), retroactive retraction, and
  `gseer suppress add/list/remove`.  IPv4/IPv6/IDNA/trailing-dot/
  label-boundary matching pinned by tests; fixture purge stays
  orthogonal.
- **Collection framework** (M14): migration 0006 (collection_jobs,
  source_checkpoints, ingestion_dead_letter, scopes), `internal/collect`
  (terms gate → checkpoints → retries/backoff → normalize/dedupe →
  suppression-gated ingestion → poison dead-lettering → job
  bookkeeping), rate-limited HTTP client with body cap + credential
  redaction, asset-only honesty contract.
- **Source reviews + connectors** (M15): `docs/SOURCES.md` register
  (verdicts enforced by code — `E_SOURCE_TERMS`); `dns` + `ip2asn`
  reviewed-enabled; `rdap` + `ct` implemented but disabled pending
  provider authorization; `gseer source list/add/enable/disable`,
  `gseer collect run/status`.
- **Security regression review of the M10 surfaces** (M16): security
  response headers on API + dashboard, trusted-proxy client-IP opt-in
  (XFF ignored by default, right-most hop through configured CIDRs,
  fail-closed parse), dashboard GET-only/CSRF-surface pin, PID-file
  identity verification + 0600.
- Milestone register entries M13–M17.

## [v0.0.1] — Search Engine Developer Preview (Phase 1)

Milestones M1–M12: GQL (lexer/parser/validator/planner), PostgreSQL
storage + migrations, SearchService, REST API + dashboard + `server
start/stop`, CLI, auth + rate limiting, fixture corpus (labeled
synthetic), quickstart/doctor/packaging, governance pins as CI tests.
No real data; no connectors; search-only (Search ≠ Scan, ADR-0010).

## v6.2 — bench harness + regression gate (r20, R140)
- `gseer bench run [--runs N] [--save] [--json]` — fixed, versioned workload set
  (point_lookup, service_filter, asn_filter, facets, relations) through the
  PRODUCTION search service; deterministic probe discovery recorded in the
  results file; 1 warmup excluded; p50/p95/p99/max per workload.
- `gseer bench compare [--file] [--tolerance] [--min-abs-ms] [--json]` —
  fail-closed p95 gate (relative ratio × AND absolute noise floor, default
  25 ms measured on the 1M corpus); REGRESSION → exit code 6 (CI-able).
- New exit code 6 (ExitBenchRegress); additive, existing codes unchanged.
- Measured on the real 1M-asset / 1.0 GiB corpus: point_lookup p50 0.5 ms,
  service_filter p95 ~250-265 ms, asn_filter p95 ~264-284 ms, facets p95
  ~315-327 ms, relations p95 ~242-248 ms. Reproducibility: real workloads
  within 2% run-to-run; sub-ms probes jitter >40% (hence the noise floor).

## v6.3 — hostname prefix search + bench-v2 (r21, R113/R140)
- Migration 0015 (personal SQLite) / 0030 (PG twin): `ix_assets_hostname_nocase`
  — hostname wildcard-prefix queries (`hostname == "api.*"`) were full scans
  (~95 ms no-match probe on 1M rows); now index-served (~0 ms).  COLLATE NOCASE
  enables SQLite's LIKE optimization; PG uses text_pattern_ops.
- bench CLI now migrates to head before measuring (was silently benchmarking
  the old schema — found during this work).
- bench-v2: hostname_prefix workload (narrow prefix + honest substring
  suffix), probe-derived, skipped on corpora without hostnames; v1 baselines
  fail closed (exit 6).  Re-baseline after upgrade.
- PG migration registry tests updated for head 0030 (0030 first applied
  collision with existing 0026_dns_searchable — caught by suite, renumbered).

## v6.4 — search relevance R114 + bench-v3 (r23)
- R114: substring-family relevance (exact > prefix > rest) as the
  DEFAULT ordering for eligible queries (single CONTAINS / *= /
  IN_DOMAIN predicate, AND-ed non-text filters allowed).  Matched set
  unchanged; ordering only.  Two-phase guard: rank only matched sets
  ≤ 50k rows (measured first; 600k-row set measured 2.8 s rank vs
  0.8 s recency on the 1M corpus), larger sets fall back to recency
  with an explicit notice; `--sort relevance:asc` forces ranking.
  Cursors carry the tier; page 2 compares the same CASE (dedicated
  three-occurrence cursor predicate — placeholders bind per textual
  occurrence, found by the pagination test).  EXPLAIN shows the rank.
  PG twin implemented (lower()/ILIKE rank, ::bigint tier cast); PG
  green path remains sandbox-blocked (R61).
- bench-v3: hostname_prefix fixed to `*=` (the v2 `==`-with-star form
  matched nothing — workload bug caught in R114 review); benchgen now
  generates TLS + CT evidence via the same generic projection the
  collectors use; tls_filter + ct_filter workloads with corpus-derived
  probes (skip honestly when data absent); v2 baselines fail closed.
## v0.3.2-r23 — release candidate (owner-accepted state)
- Package identity: v0.3.2-r23 across CLI (`gseer version`), Makefile
  default VERSION, release manifest, acceptance report and the release
  archive filename (gseer-v0.3.2-r23-release-candidate.zip).
- Content = the r23 tree exactly as owner-accepted (R114 relevance,
  bench-v3, CT projection completion); no feature changes at packaging
  time.  Build artifacts (binaries) are excluded from the source
  release; `make build` reproduces them.
## v0.3.2 — official release candidate
- Defect fix (blocking, discovered during final package validation):
  the published central-dataset manifest now carries publisher-side
  fields (e.g. `signature`) that the strict manifest decoder refused
  (`json: unknown field "signature"`) — the documented dataset
  ingestion path failed.  ParseManifest now ignores unknown manifest
  fields (forward-compatible envelope); compatibility stays gated by
  `schema_version` and payload integrity by checksums.  The CLI does
  NOT verify manifest signatures.  Regression: TestManifestUnknownFields
  + internal/dataset suite + cli Dataset/Setup/FreshInstall green.
- Built from the owner-accepted r23 state (R114 relevance, bench-v3,
  CT projection completion) with NO feature changes at packaging time.
- Identity: v0.3.2 across CLI (`gseer version`), Makefile default
  VERSION, README-RELEASE, CHANGELOG, RELEASE-MANIFEST, and the
  archive filename (gseer-v0.3.2.zip).
- Package docs completed: README-RELEASE (install workflow),
  docs/TROUBLESHOOTING (new), data-flow honesty (DATASET/SOURCES/
  SCANNING + discovered/resolved/observed distinction in
  KNOWN-LIMITATIONS).
