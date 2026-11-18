# GSEER — Central Internet Asset Dataset (v0.3.2 Rev 14)

The central dataset is the project's **scheduled passive discovery export**:
a versioned, checksummed artifact of validated evidence that the project's
GitHub Actions pipeline collects, validates, and publishes — and that your
CLI downloads, verifies, and imports into your Local Index.

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
6. exports + validates the dataset (`gseer-dataset build` + `validate` —
   validation is the publication gate);
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

Integrity model (deliberate, owner-reviewed): payload SHA-256 in the
manifest + HTTPS transport. A checksum mismatch refuses the import
outright (`E_DATASET_CHECKSUM`) and the database is not touched. There is
no third-party signing ceremony (the Rev 8 owner decision that removed
the shared-index key ceremony stands).

Default channel:
`https://github.com/Lutfifakee-Project/gseer/releases/download/central-dataset/gseer-dataset-manifest.json`
— override with `dataset.manifest_url` (config), `GSEER_DATASET_MANIFEST_URL`
(env), or `--manifest-url`. Plain `http://` is accepted ONLY for loopback
hosts (local testing).

## 4. The journey (what a user does)

```bash
gseer setup                     # provisions personal mode + imports the dataset
gseer search 'port=443'         # REAL results from the imported dataset
gseer dataset status            # installed version + freshness
gseer dataset update            # refresh WITHOUT a re-setup
gseer dataset check             # channel manifest only (no download/import)
```

`gseer setup` auto-imports the latest dataset after the local discovery
bootstrap. If the channel is unreachable, setup says so honestly
(`[warn]`), keeps working with whatever local discovery produced, and
still exits 0 — nothing is half-imported.

## 5. Import atomicity, rollback, and recovery

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

## 6. Coverage honesty

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

## 7. Commands reference

| Command | What it does | Exit codes |
| --- | --- | --- |
| `gseer dataset update [--manifest-url URL] [--force]` | download → verify → atomic import | 2 checksum/usage, 3 config, 4 unreachable/DB |
| `gseer dataset check [--manifest-url URL]` | manifest-only: version, freshness, provenance | 2/3/4 |
| `gseer dataset status` | installed version, imported_at, freshness window | 2/3/4 |

The dataset channel is a personal-Local-Index surface (the self-hosted
PostgreSQL profile refuses it with an honest `E_USAGE` pointer).
