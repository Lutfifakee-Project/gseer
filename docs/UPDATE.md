# GSEER — Signed Update System

`gseer update` upgrades a GSEER binary through a **signed update
manifest**.  Trust is anchored in an Ed25519 public key **embedded in
the binary** — never in the URL a manifest came from.  An unsigned or
wrongly-signed manifest is refused no matter how familiar the download
URL looks (owner directive §5).

## 1. The update chain (in enforcement order)

| Step | Gate | Failure code |
| --- | --- | --- |
| 1 | Manifest Ed25519 signature verifies against the embedded key | `E_UPDATE_UNSIGNED` / `E_UPDATE_BAD_SIGNATURE` |
| 2 | Manifest version is strictly newer than the running build (semver, pre-release aware; `--force` overrides) | `E_UPDATE_NOT_NEWER` / `E_UPDATE_VERSION` |
| 3 | Manifest carries an artifact for the exact running GOOS/GOARCH | `E_UPDATE_PLATFORM` |
| 4 | Downloaded payload SHA-256 and size match the manifest | `E_UPDATE_CHECKSUM` |
| 5 | Atomic rename over the running binary, mode preserved, previous binary kept as `<binary>.bak`; any failure restores the backup | `E_UPDATE_REPLACE` (with automatic rollback) |
| 6 | Post-rename durability barrier: directory fsync (dirsync.go) | `E_UPDATE_DIRSYNC` warning (replaced ≠ rolled back) |

The download is capped (512 MiB), HTTP(S)-only, timeout-bounded, and
credential-redacting (userinfo URLs are never echoed into errors).
Everything the updater writes lives next to the target binary; nothing
runs automatically afterwards — the next CLI invocation picks up the
new build.

If the rename itself succeeded but the directory fsync failed, the
updater reports `E_UPDATE_DIRSYNC`: the binary WAS replaced and nothing
was rolled back — `gseer update --apply` prints the success line plus a
`[warn]` with the fsync error and exits successfully.  The new binary's
data was already fsynced before the rename; only the directory entry is
in doubt, so after a crash or power loss the previous binary may
reappear.  Re-running the update makes the change durable again.
(The Windows MoveFileExW barrier was removed with the Windows
platform — Linux is the supported product platform.)

## 2. Commands

```bash
gseer update --check                  # verify manifest + report only (no download)
gseer update --apply                  # full chain: verify → download → checksum → replace
gseer update --apply --force          # allow same/older versions (re-install)
gseer update --manifest URL_OR_PATH   # override the configured channel
```

The manifest location comes from `update.manifest_url` (config file) or
`GSEER_UPDATE_MANIFEST_URL`.  Without a configured channel the command
fails with `E_UPDATE_NO_CHANNEL` and a pointer here.

**Update channel note (v0.3.2).** The signed-update *mechanism* is
implemented and shipped (since v0.1.0), but GSEER does **not** host an
official manifest or update feed: there is no default
`GSEER_UPDATE_MANIFEST_URL` and no `gseer update --check` success out of
the box: a fresh install has no active channel until the operator
provides and configures their own manifest URL (signed with the key
embedded in the binary, per §3–§4).
Until then, `gseer update` refuses with `E_UPDATE_NO_CHANNEL` — which is
intentional: GSEER never downloads or applies updates from an unconfigured,
unverified source.

Recovery: the previous binary is always kept at `<binary>.bak`.  If a
new build misbehaves, move the old file back:

```bash
mv gseer.bak gseer
```

## 3. Manifest format

```json
{
  "version": "v0.3.1",
  "released_at": "2026-11-03T00:00:00Z",
  "artifacts": [
    {"os": "linux", "arch": "amd64",
     "url": "https://download.example/gseer-v0.3.1-linux-amd64",
     "sha256": "<64 hex>", "size": 38777344}
  ],
  "notes_url": "https://github.com/.../releases/tag/v0.3.1",
  "signature": "<base64 Ed25519 over the canonical core bytes>"
}
```

The signature covers the **canonical core** — the manifest JSON without
the `signature` field, marshaled by Go's `encoding/json` (struct field
order is deterministic).  `gseer-release sign` performs exactly this;
the updater re-marshals the received core and verifies — any byte
changed after signing (including added fields) breaks verification.

## 4. Release process (maintainer)

```bash
go run ./cmd/gseer-release keygen -pub gseer-update.pub -priv gseer-update.key
#   → embed the PUBLIC key base64 into internal/update/keys.go
#     (EmbeddedUpdatePublicKeyB64) and release binaries built from it.
#   → the PRIVATE key (0600) stays with the release machine.  NEVER
#     commit it, never put it in CI secrets the whole team can read.
```

Per release:

```bash
# 1. compute artifact hashes
sha256sum gseer-v0.3.1-linux-amd64 gseer-v0.3.1-darwin-arm64 ...
# 2. write manifest.json (version, released_at, artifacts, notes_url)
# 3. sign
go run ./cmd/gseer-release sign -key gseer-update.key -in manifest.json -out manifest.signed.json
# 4. pre-release self-check (same verification the updater runs)
go run ./cmd/gseer-release verify -pub gseer-update.pub -in manifest.signed.json
# 5. publish manifest.signed.json + artifacts; point update.manifest_url at it
```

**Key rotation**: generate a new pair, embed the new public anchor, and
publish the new signed manifest; announce the rotation in the release
notes.  The `.bak` recovery path is independent of key state, so an
anchor rotation can never strand an installation mid-update.

## 5. Invariants (pinned by tests)

- `internal/update/update_test.go` — tampered/unsigned/foreign-key
  manifests are refused; a signed-but-wrong checksum stops the apply;
  version ordering (including `-rcN` pre-releases) is exact; platform
  selection never guesses; the replace is atomic with backup +
  rollback; URLs with credentials are redacted.
- The embedded anchor constant must decode to a valid Ed25519 public
  key (`TestBase64AnchorDecodes`) — a broken constant is a build error,
  not a runtime surprise.
- `internal/update/apply_test.go` — the durability contract: backup
  copy/sync/close error precedence, backup permission preservation, no
  temp-file leftovers, rollback (including failed-rollback reporting)
  and the dir-sync warning contract (replaced ≠ rolled back).
  (The Windows durability suite was removed with the Windows platform.)
- `gseer update` on an un-injected `dev` build refuses to act
  (`E_UPDATE_VERSION`): a binary that cannot prove its version cannot
  prove an update is an upgrade.  Release builds stamp the version via
  `-ldflags` (Makefile).

## 6. Upgrading a v0.1.0 deployment to v0.2.0 (HISTORICAL)

HISTORY (v0.2.0 era, now retired): the v0.1.0 → v0.2.0 upgrade was a
source + schema upgrade over the then-existing self-hosted PostgreSQL
runtime, automated by the hardened setup sequence of that release
(operator-DSN setup, role bootstrap, migrations to head, the
least-privilege runtime grant, and the fail-closed privilege audit).
The self-hosted (PostgreSQL) profile was RETIRED in v0.3.2 (SQLite-only
architecture), so this procedure no longer applies to any current
release and the exact commands are intentionally NOT reproduced here;
see CHANGELOG.md for the historical record.
