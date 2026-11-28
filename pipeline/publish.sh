#!/usr/bin/env bash
# GSEER shared-index pipeline — ATOMIC publication (docs/SHARED-INDEX.md
# §3 step 7).  The pointer manifest is the LAST thing that ever moves:
#
#   1. ensure the rolling release exists (created EMPTY, --latest=false)
#   2. upload the immutable snapshot asset (--clobber is safe here: the
#      pointer has NEVER named this sequence — enforced by step 4)
#   3. retrieve the uploaded snapshot and checksum-verify it
#   4. anti-rollback / concurrency gate: re-fetch the CURRENT pointer
#      manifest; it must still name our parent sequence (PREV_SEQ).
#      A pointer at or beyond our sequence means someone already
#      published/reused it — refuse (never downgrade, never reuse).
#   5. upload the pointer manifest (--clobber) — THE pointer switch
#   6. fetch the published manifest and independently verify it
#      (signature against the embedded anchor, checksum against the
#      local snapshot, sequence == SEQ, artifact name matches)
#
# A failed snapshot upload or verification NEVER advances the pointer:
# steps 1-3 leave the manifest untouched, so the published sequence the
# clients see cannot regress or point at a missing artifact.
#
# FATAL codes: 20 release create failed · 21 snapshot upload/retrieval/
# checksum failed (pointer untouched) · 22 anti-rollback/concurrency
# refusal · 23 post-publication verification failed.
#
# Env-injectable (GH_CMD/REPO/PROVIDER_BIN/WORKDIR/SEQ/PREV_SEQ/
# SNAP/MANIFEST) for offline stub testing.
set -uo pipefail

GH="${GH_CMD:-gh}"
REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
PROVIDER_BIN="${PROVIDER_BIN:-./build/gseer-provider}"
WORKDIR="${WORKDIR:-.}"
CHANNEL="shared-index"
SNAP="${SNAP:-$WORKDIR/snapshot/gseer-index-${SEQ}.db}"
MANIFEST="${MANIFEST:-$WORKDIR/snapshot/gseer-index-manifest.json}"

die() { echo "FATAL($1): $2" >&2; exit "$1"; }
info() { echo "[publish] $*" >&2; }

[ -n "$REPO" ] || die 20 "REPO/GITHUB_REPOSITORY is empty"
[ -n "${SEQ:-}" ] && [ -n "${PREV_SEQ:-}" ] || die 20 "SEQ and PREV_SEQ are required"
[ -f "$SNAP" ] || die 20 "snapshot not found: $SNAP"
[ -f "$MANIFEST" ] || die 20 "manifest not found: $MANIFEST"
[ -x "$(command -v "$GH")" ] || die 20 "gh not available: $GH"
[ -x "$PROVIDER_BIN" ] || die 20 "provider tool not found: $PROVIDER_BIN"

SNAP_NAME="gseer-index-${SEQ}.db"

# --- 1. ensure the release exists (EMPTY — assets come later) -------------
if ! "$GH" release view "$CHANNEL" -R "$REPO" >/dev/null 2>&1; then
  if ! "$GH" release create "$CHANNEL" -R "$REPO" --latest=false \
      --title "GSEER shared index (rolling pointer)" \
      --notes "Signed cumulative shared-index channel. Clients read gseer-index-manifest.json (the signed pointer) and gseer-index-<seq>.db (immutable snapshots; each sequence carries every fact of the previous one). docs/SHARED-INDEX.md" >/dev/null 2>&1; then
    die 20 "the shared-index release does not exist and could not be created"
  fi
  info "created the rolling release (empty, --latest=false)"
fi

# --- 2. upload the IMMUTABLE snapshot asset (pointer untouched) -----------
if ! "$GH" release upload "$CHANNEL" -R "$REPO" "$SNAP" --clobber >/dev/null 2>&1; then
  die 21 "snapshot upload failed — the pointer manifest is UNCHANGED (clients keep seeing the previous, healthy sequence)"
fi
info "snapshot uploaded: $SNAP_NAME"

# --- 3. retrieve + checksum-verify what was uploaded ----------------------
RETRIEVED="$WORKDIR/.retrieved-$SNAP_NAME"
rm -f "$RETRIEVED"
if ! "$GH" release download "$CHANNEL" -R "$REPO" -p "$SNAP_NAME" -O "$RETRIEVED" >/dev/null 2>&1; then
  die 21 "the uploaded snapshot cannot be retrieved — the pointer manifest is UNCHANGED (refusing to advance a pointer to an unverifiable artifact)"
fi
LOCAL_SUM=$(sha256sum "$SNAP" | cut -d' ' -f1)
REMOTE_SUM=$(sha256sum "$RETRIEVED" | cut -d' ' -f1)
if [ "$LOCAL_SUM" != "$REMOTE_SUM" ]; then
  die 21 "the retrieved snapshot checksum does not match the local artifact — the pointer manifest is UNCHANGED"
fi
rm -f "$RETRIEVED"
info "uploaded snapshot retrieved and checksum VERIFIED ($LOCAL_SUM)"

# --- 4. anti-rollback / concurrency gate on the CURRENT pointer -----------
CURRENT="$WORKDIR/.current-manifest.json"
rm -f "$CURRENT"
if "$GH" release download "$CHANNEL" -R "$REPO" -p gseer-index-manifest.json -O "$CURRENT" >/dev/null 2>&1; then
  CUR_SEQ=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("sequence"))' "$CURRENT" 2>/dev/null) \
    || die 22 "the current pointer manifest is unparseable — refusing to publish over a broken pointer"
  case "$CUR_SEQ" in ''|*[!0-9]*) die 22 "the current pointer manifest has an invalid sequence: $CUR_SEQ" ;; esac
  if [ "$CUR_SEQ" -ge "$SEQ" ]; then
    die 22 "anti-rollback: the published pointer is already at sequence $CUR_SEQ (this run builds $SEQ) — never downgrade or reuse a published sequence"
  fi
  if [ "$CUR_SEQ" != "$PREV_SEQ" ]; then
    die 22 "concurrency: the published pointer moved to sequence $CUR_SEQ (expected parent $PREV_SEQ) — another writer published mid-run; refusing"
  fi
  info "pointer re-check: still at parent sequence $PREV_SEQ — safe to advance"
else
  if [ "$PREV_SEQ" != "0" ]; then
    die 22 "the pointer manifest existed at resolve time but is now unretrievable — the channel changed mid-run; refusing"
  fi
  info "pointer re-check: no manifest yet — this publication advances the pointer to sequence 1"
fi

# --- 5. THE pointer switch (manifest upload, --clobber) -------------------
if ! "$GH" release upload "$CHANNEL" -R "$REPO" "$MANIFEST" --clobber >/dev/null 2>&1; then
  die 21 "manifest upload failed — the pointer was NOT advanced (the previous sequence remains published)"
fi
info "pointer manifest uploaded (sequence $SEQ is now the official channel head)"

# --- 6. independent post-publication verification -------------------------
sleep 3 # release asset propagation
PUBLISHED="$WORKDIR/.published-manifest.json"
rm -f "$PUBLISHED"
if ! "$GH" release download "$CHANNEL" -R "$REPO" -p gseer-index-manifest.json -O "$PUBLISHED" >/dev/null 2>&1; then
  die 23 "the published pointer manifest cannot be retrieved — inspect the release immediately"
fi
if ! "$PROVIDER_BIN" verify -manifest "$PUBLISHED" -artifact "$SNAP" >&2; then
  die 23 "the published pointer failed signature/checksum verification against the embedded trust anchor"
fi
PUB_SEQ=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("sequence"))' "$PUBLISHED" 2>/dev/null) || die 23 "the published manifest is unparseable"
PUB_ART=$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1])).get("artifact",{}).get("url","")).rstrip("/").split("/")[-1])' "$PUBLISHED" 2>/dev/null) || die 23 "the published manifest artifact URL is unreadable"
if [ "$PUB_SEQ" != "$SEQ" ] || [ "$PUB_ART" != "$SNAP_NAME" ]; then
  die 23 "post-publication mismatch: pointer says sequence $PUB_SEQ / artifact $PUB_ART, expected $SEQ / $SNAP_NAME"
fi
echo "PUBLISH_OK sequence=$SEQ artifact=$SNAP_NAME sha256=$LOCAL_SUM"
