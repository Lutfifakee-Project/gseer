# GSEER — Central Internet Asset Dataset (v0.3.2: SIGNED distribution)

The central dataset is the project's **scheduled passive discovery export**:
a versioned, SIGNED artifact of validated evidence that the project's
GitHub Actions pipeline collects, validates, signs, and publishes — and
that your CLI downloads, signature-verifies, checksum-verifies, and
imports into your Local Index (P0-1: the Ed25519 signature over the
manifest's canonical core is MANDATORY — an unsigned or tampered manifest
never reaches the import path).

**Search stays LOCAL.** The dataset only FEEDS the index; GSEER has no
shared-index query service, no API server, and no dashboard (Rev 8
architecture decision, unchanged). Search never triggers discovery,
downloading, or scanning.

## 1. The pipeline (owner-side)

`.github/workflows/dataset.yml` runs every 6 hours (and on demand):

1. builds `gseer` + `gseer-dataset` from main;
2. provisions a STAGING personal Local Index;
3. registers the seed sources from `pipeline/dataset-seeds.yaml` (the
   bootstrap coverage register — every connector is terms-reviewed per
   `docs/SOURCES.md`) and runs the passive connectors;
4. runs the SEED-FREE CT-log discovery connector (`ctlog`, §G): a
   bounded, tip-following window of a public Certificate Transparency
   log — no operator seeds; the only step whose coverage grows beyond
   the register by itself;
5. observes TLS `:443` on the seeds' web hostnames under an explicit,
   audited scope (the honesty contract reserves PORT facts to explicit
   observation — passive facts never invent ports);
6. exports, SIGNS, and validates the dataset (`gseer-dataset build`
   -key-file <seed> + `validate` — validation is the publication gate
   and REQUIRES a passing Ed25519 signature; §5);
7. publishes the artifact as the rolling `central-dataset` release
   (NON-latest; stable asset names) plus a per-run audit artifact.

End users never run the pipeline, enter seeds, or collect anything — the
`gseer setup` journey is: install → setup → search.

## 2. What is in the dataset

One **validated fact** per NDJSON line (gzip payload): the asset, the
optional service (port evidence), and the provenance-bearing observation
(source name + connector, `observed_at`, the collector's `payload_hash`,
evidence). Per-record DB identity (id, source_cursor) is stamped by the
IMPORTER at import time — the mirror of the collect runner's per-delivery
stamping — so re-imports are idempotent and the file never collides with
a store's local ids.

Validation (publication gate, enforced in `cmd/gseer-dataset` AND again
at import): schema version, known asset kinds, IP sanity, port range,
transport/protocol sanity, observed_at present and not in the future,
payload_hash present, provenance present. Fixture rows and previous
import bookkeeping rows are excluded at export.

### Row-count semantics (what each manifest number counts)

- `rows.observations` (`payload.records`) counts EVIDENCE RECORDS — one
  NDJSON line each.  A single TLS observation produces TWO records: one
  asset-level (the certificate/endpoint fact) and one service-bearing
  (the port fact), so `provenance[].records` for a scan source is 2× the
  number of scans.
- `rows.services` counts SERVICE-BEARING RECORDS (records that carry a
  service), NOT distinct service rows.  On import the service rows
  collapse onto the store's `(asset, port, transport)` identity — e.g.
  an apex domain and its `www` form behind the same IP share ONE service
  row — so the Local Index can hold FEWER service rows than
  `rows.services`.  Both numbers are honest; they count different
  things (dataset evidence vs imported identity rows).
- `rows.assets` counts DISTINCT assets in the dataset (the same
  identity the store deduplicates on).

## 3. The manifest

`gseer-dataset-manifest.json` carries everything freshness and auditing
need:

| Field | Meaning |
| --- | --- |
| `dataset_version` | monotonic sequence (the pipeline's run number) |
| `generated_at_utc` | when the artifact was produced |
| `payload.sha256 / size_bytes / records` | the integrity contract |
| `rows.assets / services / observations` | dataset-level row counts |
| `provenance[]` | per-source records + newest observed_at |
| `freshness.oldest/newest_observed_at` | the REAL evidence age window |
| `validator_version` | the validation ruleset that produced it |
| `notes` | the honest coverage statement |
| `signature` | Ed25519 over the canonical core (`algorithm`, `key_id`, base64 `value`) — §5 |

Integrity model (P0-1, the owner-mandated "signed dataset distribution"):
the manifest is SIGNED with Ed25519 — the signature covers the CANONICAL
core of the manifest (schema version, dataset version, timestamps, the
payload identity: filename + sha256 + size_bytes + records, the row
counts, provenance, and freshness), so the payload bytes are bound
unambiguously.  Verification is fail-closed at THREE layers: PARSE (an
unsigned or malformed signature block never parses —
`E_DATASET_UNSIGNED`), FETCH (the signature is verified against the key
EMBEDDED in the CLI binary before any payload download —
`E_DATASET_UNKNOWN_KEY` for an unlisted key ID,
`E_DATASET_BAD_SIGNATURE` for a tampered/foreign-signed manifest), and
IMPORT (re-verified at the import boundary, defense in depth).  A
checksum mismatch (`E_DATASET_CHECKSUM`) still refuses the import
outright, and the database is never touched.  HTTPS transport stays the
delivery rule (plain http only for loopback hosts, local testing).

Default channel:
`https://github.com/Lutfifakee-Project/gseer/releases/download/central-dataset/gseer-dataset-manifest.json`
— override with `dataset.manifest_url` (config), `GSEER_DATASET_MANIFEST_URL`
(env), or `--manifest-url`. Plain `http://` is accepted ONLY for loopback
hosts (local testing).

## 4. The journey (what a user does)

```bash
gseer search "apache"           # the ONE-command experience: the FIRST search
                                # auto-imports the SIGNED dataset, then queries it
gseer setup                     # provisions personal mode + bootstraps discovery + imports the dataset
gseer search 'port=443'         # REAL results from the imported dataset
gseer search 'port:443'         # simple field shorthand — the same row
gseer dataset status            # installed version + freshness
gseer dataset update            # refresh WITHOUT a re-setup
gseer dataset check             # channel manifest only (signature verified; no payload download)
```

`gseer setup` imports the latest dataset as its MANDATORY final stage
(after the passive discovery bootstrap): the SIGNED manifest is fetched
and verified against the embedded key, the payload is checksummed, and
the import is atomic.  A failed fetch, signature, checksum, or import
FAILS the setup (non-zero exit, `E_DATASET_SETUP_FAILED`) — the dataset
is never reported as ready when it is not.  Search NEVER fetches
anything: it stays query-only over the local index.  Explicit offline
operation: `gseer setup --offline` skips the dataset stage and reports
the dataset state as NOT INSTALLED.  Retry any time:
`gseer dataset update`.

Redirects are validated on EVERY hop (limit, no HTTPS→HTTP downgrade,
no private/loopback/link-local destinations) and a cross-host hop is
refused unless the target host is explicitly trusted.  The official
channel's hop (`github.com/…/releases/download/…` → the GitHub
release-asset CDN `release-assets.githubusercontent.com`) is trusted by
default; an explicit `dataset.trusted_redirect_hosts` list in the
config replaces that default verbatim (exact hostnames only — an empty
list trusts nothing).  Trust never weakens the download itself: the
manifest signature, the payload size and SHA-256, and the HTTPS
transport of every hop are enforced regardless of which host serves
the bytes.

## 5. Signing and key management (the ceremony)

- **Key generation** — the owner runs `gseer-dataset keygen -out seed`:
  a 32-byte Ed25519 seed is written to the seed file (0600 — the PRIVATE
  half lives ONLY in the CI secret store `GSEER_DATASET_SIGNING_KEY`;
  never in the repository, the source tree, or any artifact), and the
  PUBLIC half + the stable key ID (`hex(sha256(pub)[:8])`) print for
  embedding into `internal/dataset/keys.go` before the release is cut.
- **Signing** — the pipeline signs each manifest at build time
  (`gseer-dataset build -key-file <seed>`, or `gseer-dataset sign -dir
  <artifact>` afterwards); the seed is consumed in memory only.  The
  signature covers the canonical manifest core — including the payload
  sha256/size/records — so the binding is unambiguous.
- **The publication gate** — `gseer-dataset validate` refuses an
  unsigned artifact: fail-closed by construction (no "publish now, sign
  later").
- **Verification (consumer)** — the CLI's keyring (`internal/dataset/
  keys.go`) is EMBEDDED in the binary; the manifest's
  `signature.key_id` selects the trusted key.  An unknown key ID is a
  refusal, never a guess.

## 6. Rotation and recovery

- **Planned rotation** — generate a new keypair (`gseer-dataset
  keygen`), ADD its public key + key ID to the embedded keyring (keep
  the previous entry: in-flight manifests keep verifying), publish the
  next dataset version signed with the new key, and remove the old
  entry after the FOLLOWING version has shipped.  Key IDs are stable,
  so both keys coexist inside one rotation window.
- **Compromised key** — rotate immediately: publish the next version
  signed with the new key and remove the compromised entry from the
  ring in a released binary.  A compromised key can only inject
  manifests until its entry is gone from the binary consumers run; the
  monotonic version gate limits the damage on clients already holding a
  newer version.
- **Lost seed** — no data loss: installed datasets keep working (§7
  freshness policy), and the pipeline generates a replacement keypair
  through the ceremony above; consumers upgrade when the ring changes.
- **Offline resilience** — an installed dataset keeps answering
  searches regardless of channel availability; freshness is reported
  honestly (`gseer dataset status`), and the automatic bootstrap paces
  its retries so an offline machine never stalls.

## 7. Import atomicity, rollback, and recovery

The import is ALL-OR-NOTHING:

1. **Recovery** — a leftover `<db>.dataset-import-backup` snapshot from
   an interrupted import is restored first (the previous import never
   half-landed; stale `-wal`/`-shm` sidecars are removed with it);
2. **Snapshot** — `VACUUM INTO` takes a byte-identical, `0600` pre-import
   image next to the live database;
3. **Stream + ingest** — records flow through the SAME ingestion path as
   every other writer (suppression gate, delivery-identity dedupe,
   per-source provenance);
4. **Verify** — streamed record count must equal the manifest's;
5. **Rollback** — any failure (bad record, count mismatch) replaces the
   live database with the snapshot (same-directory rename);
6. **Record** — success records the install (version, counts, checksum,
   freshness) on the `central-dataset` bookkeeping source; the snapshot
   is removed.

Idempotency: re-importing the SAME dataset version dedupes at the
delivery identity (0 inserted / N deduped); re-importing a NEWER version
whose evidence is unchanged ALSO dedupes at the L2 fact identity (same
content, same observed_at) — only genuinely new evidence lands. The
version gate refuses older/equal versions without `--force`.

## 8. Coverage honesty

Coverage has two layers, both stated honestly in the manifest's `notes`:

1. **The seed register** (`pipeline/dataset-seeds.yaml`) — 14 seed
   domains, of which **4 are DNS-only** (`scanme.nmap.org`,
   `scanme.insecure.org`, `neverssl.com`, `gnu.org`) and 10 form the
   `tls_hosts` subset for active TLS :443 observation, each with a
   documented terms basis in the register header (IANA documentation
   domains, public test services, public DNS services, and public web
   properties under a single audited handshake per target per run).
   Passive DNS resolution runs over ALL 14; the active TLS observation
   runs over the 10 only.
2. **The seed-free CT-log window** (`ctlog`, `docs/SOURCES.md` §G) — a
   bounded, tip-following read of a public Certificate Transparency log
   (RFC 9162 §5 mandates the public APIs; certificates are public
   data).  Every DNS name in the freshest certificates lands as a
   hostname sighting with full provenance (log, entry index, leaf
   SHA-256, cert timeline).  This layer needs NO seeds and is the only
   part of the pipeline that grows beyond the register by itself.

That is real internet evidence (real DNS answers, real TLS certificates,
real IPs, real logged certificates), and it is NOT internet-wide
coverage: the manifest's `notes` says so.  Passive DNS seeds are never
actively probed; active observation targets must be a subset of the
register (enforced by the workflow's seed parser); CT names are never
contacted by the discovery itself.  `gseer dataset check` prints the
per-source provenance and freshness so the operator can see exactly what
the channel offers.

## 9. Commands reference

| Command | What it does | Exit codes |
| --- | --- | --- |
| `gseer dataset update [--manifest-url URL] [--force]` | fetch → SIGNATURE verify → checksum verify → atomic import | 2 signature/checksum/usage, 3 config, 4 unreachable/DB |
| `gseer dataset check [--manifest-url URL]` | manifest-only: version, SIGNATURE, freshness, provenance | 2/3/4 |
| `gseer dataset status` | installed version, imported_at, freshness window | 2/3/4 |

`gseer-dataset` (maintainer-side) builds, signs, and validates the
artifact: `keygen`, `build -key-file`, `sign -dir`, `validate -dir`.

The dataset channel is a personal-Local-Index surface (the self-hosted
PostgreSQL profile refuses it with an honest `E_USAGE` pointer).
