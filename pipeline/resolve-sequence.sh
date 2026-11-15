#!/usr/bin/env bash
# GSEER shared-index pipeline — sequence resolution + cumulative-base
# verification (fail-closed).  docs/SHARED-INDEX.md §3 step 1.
#
# Decides ONE of three mutually exclusive modes:
#   boot        the shared-index release is CONFIRMED absent (release
#               view AND the releases API agree) → sequence 1, fresh scan.
#   cumulative  the release exists and its pointer manifest + snapshot
#               artifact are retrievable AND fully verified (signature,
#               checksum, sequence, schema, integrity, counts) →
#               restore the verified snapshot as the working store.
#   fresh       ONLY when FORCE_FRESH=true (explicit owner-triggered
#               workflow_dispatch input): the manifest is still read
#               (monotonic numbering), but the restore is skipped.
#
# Fail-closed discipline (the run DIES, nothing is published):
#   10  the API is unreachable — a missing release cannot be
#       distinguished from a network/auth failure
#   11  the release exists but the pointer manifest is unretrievable
#   12  the manifest is unparseable or its sequence is not an integer >= 1
#   13  the snapshot artifact named by the pointer is unretrievable
#   14  signature or checksum verification failed
#   15  snapshot integrity/schema/counts gate failed (gseer-provider inspect)
#   16  channel inconsistency (release-view/API disagreement, or the
#       manifest's artifact URL does not name the expected snapshot file)
#
# NEVER: silently reset the sequence to 1, downgrade, or reuse a
# published sequence.  A nonexistent release is the ONLY bootstrap path.
#
# Testability: every external dependency is env-injectable (GH_CMD,
# PROVIDER_BIN, REPO, WORKDIR), so the negative matrix is exercised
# offline by scripts/v032-sequence-acceptance.sh with a stub gh.
set -uo pipefail

GH="${GH_CMD:-gh}"
REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
PROVIDER_BIN="${PROVIDER_BIN:-./build/gseer-provider}"
WORKDIR="${WORKDIR:-.}"
FORCE_FRESH="${FORCE_FRESH:-false}"
CHANNEL="shared-index"

die() { echo "FATAL($1): $2" >&2; exit "$1"; }
info() { echo "[resolve] $*" >&2; }

[ -n "$REPO" ] || die 10 "REPO/GITHUB_REPOSITORY is empty"
[ -x "$(command -v "$GH")" ] || die 10 "gh not available: $GH"
[ -x "$PROVIDER_BIN" ] || die 10 "provider tool not found: $PROVIDER_BIN"

mkdir -p "$WORKDIR/prev"

release_view() { "$GH" release view "$CHANNEL" -R "$REPO" >/dev/null 2>&1; }

# --- probe: can we talk to the API at all? --------------------------------
api_ok() {
  "$GH" api rate_limit -R "$REPO" >/dev/null 2>&1 ||
    "$GH" api "repos/$REPO" >/dev/null 2>&1
}

release_listed() {
  "$GH" api "repos/$REPO/releases" 2>/dev/null |
    python3 -c 'import json,sys
try:
    rs = json.load(sys.stdin)
except Exception:
    sys.exit(2)
sys.exit(0 if any(r.get("tag_name") == "shared-index" for r in rs) else 1)'
}

if release_view; then
  RELEASE_EXISTS=true
else
  if ! api_ok; then
    die 10 "the GitHub API is unreachable — a genuinely missing release cannot be distinguished from a network/auth failure; refusing to bootstrap (never silently reset the sequence)"
  fi
  if release_listed; then
    die 16 "release view failed but the releases API still lists shared-index — inconsistent channel state; fail closed"
  fi
  RELEASE_EXISTS=false
fi

if [ "$RELEASE_EXISTS" = "false" ]; then
  info "boot: the shared-index release does not exist (view + API agree) — this is sequence 1 (fresh scan)"
  echo "RESTORE_MODE=boot"
  echo "PREV_SEQ=0"
  echo "SEQ=1"
  exit 0
fi

# --- release exists: the pointer manifest MUST be retrievable -------------
MANIFEST="$WORKDIR/prev/gseer-index-manifest.json"
if ! "$GH" release download "$CHANNEL" -R "$REPO" -p gseer-index-manifest.json -O "$MANIFEST" >/dev/null 2>&1; then
  die 11 "the shared-index release exists but its pointer manifest cannot be retrieved — fail closed (a broken channel halts the pipeline; coverage is never silently erased)"
fi

PREV_SEQ=$(python3 - "$MANIFEST" <<'PY'
import json, sys
try:
    m = json.load(open(sys.argv[1]))
except Exception as e:
    print(f"ERR:{e}"); sys.exit(0)
s = m.get("sequence")
if not isinstance(s, int) or isinstance(s, bool):
    print("ERR:sequence is not an integer"); sys.exit(0)
print(s)
PY
) || die 12 "cannot read the pointer manifest"
case "$PREV_SEQ" in ERR:*) die 12 "invalid pointer manifest: ${PREV_SEQ#ERR:}" ;; esac
if [ "$PREV_SEQ" -lt 1 ] 2>/dev/null; then
  die 12 "the pointer manifest's sequence must be >= 1 (got $PREV_SEQ)"
fi
SEQ=$((PREV_SEQ + 1))
info "pointer manifest verified parseable: sequence $PREV_SEQ → this run builds sequence $SEQ"

if [ "$FORCE_FRESH" = "true" ]; then
  info "fresh: FORCE_FRESH=true (explicit owner-triggered recovery) — monotonic numbering kept (SEQ=$SEQ), restore SKIPPED"
  echo "RESTORE_MODE=fresh"
  echo "PREV_SEQ=$PREV_SEQ"
  echo "SEQ=$SEQ"
  exit 0
fi

# --- consistency: the pointer must name exactly the expected artifact -----
ART_NAME="gseer-index-${PREV_SEQ}.db"
URL_BASENAME=$(python3 - "$MANIFEST" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
url = str(m.get("artifact", {}).get("url", "")).rstrip("/")
print(url.split("/")[-1] if url else "")
PY
) || die 12 "cannot read the manifest artifact URL"
if [ -z "$URL_BASENAME" ] || [ "$URL_BASENAME" != "$ART_NAME" ]; then
  die 16 "channel inconsistency: the pointer manifest names artifact '$URL_BASENAME' but sequence $PREV_SEQ requires '$ART_NAME' — fail closed"
fi

# --- restore: signature → checksum → integrity/schema/counts --------------
SNAP="$WORKDIR/prev/$ART_NAME"
if ! "$GH" release download "$CHANNEL" -R "$REPO" -p "$ART_NAME" -O "$SNAP" >/dev/null 2>&1; then
  die 13 "the pointer manifest names $ART_NAME but the artifact cannot be retrieved — fail closed (fix the channel or dispatch with force_fresh=true explicitly)"
fi

if ! "$PROVIDER_BIN" verify -manifest "$MANIFEST" -artifact "$SNAP" >&2; then
  die 14 "the cumulative base failed signature/checksum verification — fail closed (possible channel tampering; a human must look at the release)"
fi

if ! "$PROVIDER_BIN" inspect -snapshot "$SNAP" -manifest "$MANIFEST" >&2; then
  die 15 "the cumulative base failed the integrity/schema/counts gate — fail closed"
fi

info "cumulative base VERIFIED (signature, checksum, sequence, schema, integrity, counts): $SNAP"
echo "RESTORE_MODE=cumulative"
echo "PREV_SEQ=$PREV_SEQ"
echo "SEQ=$SEQ"
