# GSEER — Shared Index (v0.3.2)

> The approved shared-index architecture: the project's scheduled
> pipeline builds a **versioned, signed SQLite snapshot** of the
> collected internet-asset index and publishes it; the CLI downloads,
> verifies, and imports it — so `gseer search` returns real indexed
> internet assets with zero manual collection.

## 1. What the shared index is

A personal-mode SQLite database file, exported verbatim from the
provider pipeline's store, plus a small signed manifest.  The pipeline
is CUMULATIVE: each sequence is built on top of the previously
published snapshot (restored as the working store after full trust
verification), so sequence N carries every fact of sequence N-1 plus
the new discovery — a fresh client's first import sees the whole
accumulated coverage, not just the last scan.

The client imports snapshot rows into the local personal store through
the SAME
upsert/dedup contracts live collection uses — provenance is preserved
and every imported row is labeled:

- assets gain a `shared-index` entry in their `sources` list;
- observations carry `provenance = shared-index`;
- search results therefore honestly show WHERE each fact came from.

## 2. Trust chain (verification FIRST, download LAST)

Mirrors the signed binary updater (`docs/UPDATE.md`) — an index is
only as trustworthy as the key embedded in the binary, never as the
URL it was fetched from:

| # | Gate | Refusal code |
| --- | --- | --- |
| 1 | SIGNATURE — Ed25519 over the canonical manifest bytes, verified against the key embedded in the binary | `E_INDEX_UNSIGNED` / `E_INDEX_BAD_SIGNATURE` (exit 5) |
| 2 | SEQUENCE — strictly newer than the installed one (`--force` overrides) | refused with an up-to-date report |
| 3 | CHECKSUM — SHA-256 + size must match the manifest exactly | `E_INDEX_CHECKSUM` |
| 4 | VALIDITY — SQLite `integrity_check`, schema never NEWER than this build, and the exact row counts the manifest claims | `E_INDEX_SCHEMA` / `E_INDEX_INTEGRITY` |
| 5 | ATOMIC INSTALL — staged file fsynced, then renamed into place; the previous snapshot kept as `.prev` | install failures leave the previous index intact |
| 6 | IMPORT — merge through L1 (delivery identity) + L2 (fact identity) dedup; re-import of the same snapshot is a no-op | `E_INDEX_IMPORT` |

**KEY CEREMONY (mandatory before publishing a production index):**
the owner generates a dedicated Ed25519 keypair with
`gseer-provider keygen`, keeps the PRIVATE key in the pipeline secret
store (`INDEX_SIGNING_KEY`), and ships the matching PUBLIC half in
release builds:

```bash
go build -ldflags "-X github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64=<prod-pub-b64>" \
    -o gseer ./cmd/gseer
```

The bootstrap anchor in `internal/index/keys.go` was generated for the
v0.3.2 acceptance pipeline and is a TEST anchor until this ceremony
replaces it.  Rotation = new keypair + new embedded anchor + a signed
revocation note in the release channel.  The index key is SEPARATE
from the binary-update key (`cmd/gseer-release`).

## 3. Cumulative publication model (provider side)

Maintained by `.github/workflows/index.yml` (weekly schedule +
`workflow_dispatch` with the explicit `force_fresh` recovery input).
The channel state is resolved by `pipeline/resolve-sequence.sh` and the
publication is performed by `pipeline/publish.sh`; both are fail-closed
and covered by `scripts/v032-sequence-acceptance.sh`:

1. **Channel-state resolution — exactly one of three modes.**
   `boot` (the release is CONFIRMED absent: `gh release view` fails AND
   the releases API agrees; an unreachable API is FATAL — a missing
   release is never guessed) → sequence 1, fresh scan.  `cumulative`
   (the pointer manifest + snapshot artifact are retrieved and fully
   verified) → restore.  `fresh` (ONLY the explicit owner-dispatched
   `force_fresh` input; never an automatic fallback) → skip the
   restore, keep monotonic numbering.  The release existing but its
   manifest being unretrievable is FATAL — the pipeline never resets
   the sequence to 1, never downgrades, and never reuses a published
   sequence.
2. **Cumulative base verification** — signature (Ed25519 against the
   anchor embedded in the freshly built binaries), checksum (SHA-256),
   sequence sanity (≥ 1, pointer names exactly the expected artifact),
   schema position (never NEWER than this build — `gseer-provider
   inspect`), SQLite `integrity_check`, and counts vs the signed
   manifest.  ANY failure halts the run: the pipeline refuses to
   publish a fresh scan that would silently erase prior coverage.
3. **Restore** — the verified snapshot file IS the working store (same
   schema; facts, provenance, and evidence restored verbatim;
   operational state such as collection checkpoints is deliberately not
   part of a snapshot).
4. **Incremental discovery** through the **reviewed-enabled connectors
   only** (`dns`, `ptr`, `ip2asn`) over the owner-curated seed corpus
   (`pipeline/seeds/domains.txt`) — collected on top of the restored
   base.  Merge/deduplication and ASN enrichment go through the
   standard store contracts (upsert: first_seen preserved, last_seen =
   GREATEST, stale cleared on a fresh sighting, enrichment
   COALESCE-merged) — re-collecting restored facts is idempotent;
   changes land as updates, and historical facts stay with their
   evidence.
5. Authorized observation runs ONLY when the owner commits
   `pipeline/scopes.txt` (explicit per-target authorization);
   otherwise the run is 100% passive.  Every allow/deny is audited.
6. `gseer-provider build` exports the (now cumulative) snapshot;
   `InspectSnapshot` runs `integrity_check` before anything is signed.
7. `gseer-provider manifest` builds + signs the manifest (sequence =
   previous + 1); `gseer-provider verify` re-verifies before upload.
8. **ATOMIC publication** (`pipeline/publish.sh`): the pointer
   manifest is the LAST thing that ever moves — (a) ensure the rolling
   `shared-index` release exists (created EMPTY, `--latest=false` so
   binary releases stay the headline release); (b) upload the
   IMMUTABLE snapshot asset `gseer-index-<seq>.db`; (c) retrieve the
   uploaded snapshot and checksum-verify it; (d) anti-rollback gate —
   re-fetch the CURRENT pointer: it must still name the parent
   sequence, and a pointer already at or beyond this run's sequence
   REFUSES the publication (never downgrade, never reuse, no
   concurrent pointer move); (e) upload the pointer manifest
   (`--clobber`) — the switch; (f) fetch the published manifest and
   independently verify it.  A failed snapshot upload or verification
   NEVER advances the pointer: clients keep seeing the previous,
   healthy sequence.  **Rollback = re-pointing the manifest to the
   previous sequence.**

Recovery: a publication that dies mid-run leaves the previous sequence
published (the manifest is replaced last).  The next run re-derives
the sequence from the manifest and re-uploads its artifact under the
same name.  `force_fresh=true` on a manual dispatch rebuilds from a
fresh scan while keeping sequence numbering monotonic.

Actions artifacts are never used as durable storage (retention limits;
`docs/SOURCES.md`).

## 4. Client usage

```bash
gseer setup               # fresh machine: personal mode + the shared index
gseer index update        # fetch → verify → install → import (idempotent)
gseer index update --check
gseer index status        # sequence, built_at, age, imported flag
gseer doctor              # reports the shared-index freshness contract
```

Configuration (personal profile only):

```yaml
index:
  manifest_url: https://github.com/Lutfifakee-Project/gseer/releases/download/shared-index/gseer-index-manifest.json
```

Empty means the official channel.  `GSEER_INDEX_MANIFEST_URL`
overrides.  Plain `http://` is accepted ONLY for loopback hosts (local
testing); the signature still carries the trust.

Failure behavior: network/availability failures during `setup` are
`[warn]` + continue (the engine works offline; retry is one command);
trust failures (unsigned / bad signature) REFUSE with exit 5 — an
untrusted index is never applied, silently skipped, or downgraded to a
warning.

## 5. Freshness and rollback (client side)

- `gseer index status` / `gseer doctor` surface sequence, build time,
  age (a two-weeks-plus index is a HINT), and the imported flag.
- The client keeps ONE previous generation: the current snapshot is
  renamed to `gseer-index.db.prev` before the new one takes its place.
- Downgrades are refused without `--force`; `--force` re-installs and
  re-imports (the import is idempotent).

## 6. Search fields fed by the shared index

Everything in `docs/SEARCH-SYNTAX.md` that the pipeline data carries:
identity (`ip`, `domain`, `hostname`, `host`), enrichment (`asn`,
`org`, `country` / `ip_country`, `region`, `city`), history
(`first_seen`, `last_seen`, `after` / `before`), and — for
pipeline-scanned targets — HTTP/TLS metadata, certificate fields
(`cert.sn`, `cert.domain`, `tls.version`, `cert.*.cn`,
`cert.not_after.*`) and `technologies`.
