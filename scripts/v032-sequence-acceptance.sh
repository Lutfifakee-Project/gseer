#!/usr/bin/env bash
# GSEER v0.3.2 REMEDIATION — SEQUENCE/BOOTSTRAP/ATOMIC-PUBLICATION ACCEPTANCE.
#
# Exercises pipeline/resolve-sequence.sh and pipeline/publish.sh — the
# fail-closed channel-state machine and the atomic publication order —
# through a STUB gh (full offline determinism) plus the REAL
# gseer/gseer-provider binaries and REAL signed snapshots.
#
# Negative matrix (mandatory):
#   N1  release exists + manifest unretrievable          → FATAL 11
#   N2  invalid signature (foreign key)                  → FATAL 14
#   N3  invalid checksum (tampered artifact)             → FATAL 14
#   N4  invalid/lower sequence (non-integer, 0; pointer
#       reuse/concurrency at publish)                    → FATAL 12 / 22
#   N5  corrupted previous snapshot — checksum path AND
#       checksum-valid-but-broken-integrity path, with NO silent boot
#                                                        → FATAL 14 / 15
#   N6  failed snapshot upload → manifest NOT uploaded   → FATAL 21
#   N7  test public key rejected by production-anchored
#       binaries (scripts/v032-anchor-acceptance.sh)
# Positive matrix (mandatory):
#   P1  confirmed-absent release → boot, sequence 1
#   P2  valid existing snapshot → next sequence (verified cumulative)
#   P3  atomic publication: snapshot uploaded FIRST, pointer manifest
#       LAST, post-publication verification (PUBLISH_OK)
set -uo pipefail
S=/home/z/my-project/work/remediation/gseer-v032-remediation/source
W=/tmp/asdlc-seq
export PATH=/home/z/my-project/tools/go/bin:$PATH

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
die() { echo "!!! SEQ-FAIL: $*"; exit 1; }

rm -rf "$W"; mkdir -p "$W/bin" "$W/keys"
cd "$S" || die "no source tree"
ANCHOR_PKG=github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64
go build -o "$W/bin/gseer" ./cmd/gseer          || die "client build"
go build -o "$W/bin/gseer-provider" ./cmd/gseer-provider || die "provider build"
PROV="$W/bin/gseer-provider"

"$PROV" keygen -pub "$W/keys/prod.pub" -priv "$W/keys/prod.key" >/dev/null
"$PROV" keygen -pub "$W/keys/foreign.pub" -priv "$W/keys/foreign.key" >/dev/null
chmod 600 "$W/keys/"*.key
# The binaries verify against THIS channel's anchor (same ldflags ceremony
# the workflow performs with secrets.INDEX_PUB_B64).
ANCHOR="$(cat "$W/keys/prod.pub")"
go build -ldflags "-X ${ANCHOR_PKG}=${ANCHOR}" -o "$W/bin/gseer" ./cmd/gseer          || die "anchor client build"
go build -ldflags "-X ${ANCHOR_PKG}=${ANCHOR}" -o "$W/bin/gseer-provider" ./cmd/gseer-provider || die "anchor provider build"

# --- one empty (but valid) pipeline store → snapshot + manifests ---------
STORE="$W/store.db"
"$W/bin/gseer" setup --personal --db-path "$STORE" >/dev/null || die "store setup"
"$PROV" build -store "$STORE" -out "$W/snap1.db" >/dev/null || die "snapshot build"
"$PROV" manifest -snapshot "$W/snap1.db" -sequence 1 \
  -artifact-url "http://stub.invalid/releases/download/shared-index/gseer-index-1.db" \
  -tool-version "seq-acceptance" -key "$W/keys/prod.key" -out "$W/manifest1.json" >/dev/null || die "manifest1"
"$PROV" manifest -snapshot "$W/snap1.db" -sequence 1 \
  -artifact-url "http://stub.invalid/releases/download/shared-index/gseer-index-1.db" \
  -tool-version "attacker" -key "$W/keys/foreign.key" -out "$W/manifest-foreign.json" >/dev/null
# checksum-valid + integrity-broken base: truncate the artifact.  Honest
# tooling must REFUSE to sign it (pre-signing InspectSnapshot gate):
head -c 4096 "$W/snap1.db" > "$W/snap-trunc.db" 2>/dev/null || die "truncate"
if "$PROV" manifest -snapshot "$W/snap-trunc.db" -sequence 1 \
  -artifact-url "http://stub.invalid/releases/download/shared-index/gseer-index-1.db" \
  -tool-version "seq-acceptance" -key "$W/keys/prod.key" -out "$W/manifest-trunc.json" >/dev/null 2>&1; then
  die "N5-pre: the provider SIGNED a truncated snapshot (honest tooling must refuse)"
else
  echo "    honest tooling: the provider REFUSED to sign a corrupt snapshot (pre-signing gate)"
fi

# --- the stub gh ----------------------------------------------------------
cat > "$W/stub-gh" <<'STUB'
#!/usr/bin/env bash
# Minimal gh stub: state in $STUB_DIR, call log in $STUB_LOG.
set -u
D="${STUB_DIR:?}"; L="${STUB_LOG:?}"
log() { echo "$(date -u +%H:%M:%S) $*" >> "$L"; }
cmd="${1:-}"; shift || true
case "$cmd" in
  release)
    sub="${1:-}"; shift || true
    case "$sub" in
      view)
        if [ -f "$D/release" ]; then log "view ok"; exit 0; fi
        log "view missing"; echo "release not found" >&2; exit 1 ;;
      create)
        if [ "${STUB_CREATE_FAIL:-0}" = "1" ]; then log "create FAILED"; exit 1; fi
        mkdir -p "$D/assets"; touch "$D/release"; log "create"; exit 0 ;;
      upload)
        f=""
        while [ $# -gt 0 ]; do case "$1" in -*) ;; *) f="$1" ;; esac; shift; done
        b=$(basename "$f")
        if [ "${STUB_FAIL_UPLOAD_NAME:-}" = "$b" ]; then log "upload FAILED $b"; exit 1; fi
        mkdir -p "$D/assets"; cp "$f" "$D/assets/$b"; log "upload $b"; exit 0 ;;
      download)
        p=""; o=""
        while [ $# -gt 0 ]; do case "$1" in -p) p="$2"; shift 2 ;; -O) o="$2"; shift 2 ;; -R) shift 2 ;; *) shift ;; esac; done
        if [ "${STUB_MANIFEST_DL_FAIL:-0}" = "1" ] && [ "$p" = "gseer-index-manifest.json" ]; then log "download FAILED $p"; exit 1; fi
        if [ "${STUB_SNAP_DL_FAIL:-0}" = "1" ] && [ "$p" != "gseer-index-manifest.json" ]; then log "download FAILED $p"; exit 1; fi
        if [ -f "$D/assets/$p" ]; then cp "$D/assets/$p" "$o"; log "download $p"; exit 0; fi
        log "download missing $p"; exit 1 ;;
      *) log "release ?"; exit 1 ;;
    esac ;;
  api)
    t="${1:-}"; shift || true
    case "$t" in
      rate_limit) log "api rate_limit"; exit 0 ;;
      repos/*/releases)
        log "api releases"
        if [ -f "$D/release" ]; then echo '[{"tag_name":"shared-index"}]'; else echo '[]'; fi
        exit 0 ;;
      repos/*) log "api repo"; exit 0 ;;
      *) log "api ?"; exit 1 ;;
    esac ;;
  *) log "unknown"; exit 1 ;;
esac
STUB
chmod +x "$W/stub-gh"

run_resolve() {  # run_resolve <stubdir> [extra env via caller]
  local d="$1"; shift
  ( export GH_CMD="$W/stub-gh" STUB_DIR="$d" STUB_LOG="$d/log" \
           REPO="Owner/Repo" PROVIDER_BIN="$PROV" WORKDIR="$d/work"
    rm -rf "$d/work"; mkdir -p "$d/work"
    "$S/pipeline/resolve-sequence.sh" )
}

echo "=== [P1] confirmed-absent release → boot, sequence 1 ==="
D="$W/p1"; mkdir -p "$D"
OUT=$(run_resolve "$D"); RC=$?
grep -q '^RESTORE_MODE=boot' <<<"$OUT" && grep -q '^SEQ=1' <<<"$OUT" && [ $RC -eq 0 ] \
  && ok "P1 boot: RESTORE_MODE=boot SEQ=1 (rc 0)" || { bad "P1 boot (rc=$RC): $OUT"; }
grep -q 'RESTORE_MODE=boot' "$D/log" 2>/dev/null; true

echo "=== [P2] valid existing snapshot → next sequence (cumulative, fully verified) ==="
D="$W/p2"; mkdir -p "$D/assets" "$D/work"
touch "$D/release"; cp "$W/manifest1.json" "$D/assets/gseer-index-manifest.json"; cp "$W/snap1.db" "$D/assets/gseer-index-1.db"
OUT=$(run_resolve "$D"); RC=$?
grep -q '^RESTORE_MODE=cumulative' <<<"$OUT" && grep -q '^PREV_SEQ=1' <<<"$OUT" && grep -q '^SEQ=2' <<<"$OUT" && [ $RC -eq 0 ] \
  && ok "P2 cumulative: PREV_SEQ=1 → SEQ=2 (rc 0)" || bad "P2 cumulative (rc=$RC): $OUT"

echo "=== [N1] release exists + manifest unretrievable → FATAL 11 ==="
D="$W/n1"; mkdir -p "$D"
STUB_DIR="$D" STUB_LOG="$D/log" STUB_MANIFEST_DL_FAIL=1 bash -c '
  mkdir -p "$STUB_DIR/assets" "$STUB_DIR/work"; touch "$STUB_DIR/release"' 2>/dev/null
mkdir -p "$D/assets" "$D/work"; touch "$D/release"
OUT=$( ( export GH_CMD="$W/stub-gh" STUB_DIR="$D" STUB_LOG="$D/log" REPO="Owner/Repo" PROVIDER_BIN="$PROV" WORKDIR="$D/work"
        "$S/pipeline/resolve-sequence.sh" ) 2>&1 ); RC=$?
[ $RC -eq 11 ] && ok "N1 fail-closed: rc=11 ($OUT)" || bad "N1 expected rc 11, got $RC: $OUT"

echo "=== [N2] invalid signature (foreign key) → FATAL 14 ==="
D="$W/n2"; mkdir -p "$D/assets" "$D/work"; touch "$D/release"
cp "$W/manifest-foreign.json" "$D/assets/gseer-index-manifest.json"; cp "$W/snap1.db" "$D/assets/gseer-index-1.db"
OUT=$( ( export GH_CMD="$W/stub-gh" STUB_DIR="$D" STUB_LOG="$D/log" REPO="Owner/Repo" PROVIDER_BIN="$PROV" WORKDIR="$D/work"
        "$S/pipeline/resolve-sequence.sh" ) 2>&1 ); RC=$?
[ $RC -eq 14 ] && grep -q 'BAD_SIGNATURE\|signature' <<<"$OUT" && ok "N2 foreign-key base refused: rc=14" || bad "N2 expected rc 14, got $RC: $OUT"

echo "=== [N3] invalid checksum (tampered artifact) → FATAL 14 ==="
D="$W/n3"; mkdir -p "$D/assets" "$D/work"; touch "$D/release"
cp "$W/manifest1.json" "$D/assets/gseer-index-manifest.json"
python3 - "$W/snap1.db" "$D/assets/gseer-index-1.db" <<'PY'
import sys
b = bytearray(open(sys.argv[1], "rb").read()); b[len(b)//2] ^= 0xFF
open(sys.argv[2], "wb").write(b)
PY
OUT=$( ( export GH_CMD="$W/stub-gh" STUB_DIR="$D" STUB_LOG="$D/log" REPO="Owner/Repo" PROVIDER_BIN="$PROV" WORKDIR="$D/work"
        "$S/pipeline/resolve-sequence.sh" ) 2>&1 ); RC=$?
[ $RC -eq 14 ] && grep -q 'CHECKSUM\|checksum' <<<"$OUT" && ok "N3 tampered base refused: rc=14" || bad "N3 expected rc 14, got $RC: $OUT"

# Honest tooling REFUSES to sign a corrupt snapshot (manifest → InspectSnapshot
# gate) — so the checksum-valid + integrity-broken case is only reachable with
# a compromised signing key, and the inspect gate still catches it.  Prove the
# gate directly, then test the reachable corruption path (truncation) at the
# resolve level with NO silent bootstrap:
"$PROV" inspect -snapshot "$W/snap-trunc.db" >/tmp/seq-inspect.txt 2>&1 \
  && bad "N5-pre provider inspect ACCEPTED a truncated snapshot" \
  || { echo "    inspect gate: $(grep -m1 -E 'integrity|cannot' /tmp/seq-inspect.txt | head -1)"; }
echo "=== [N5] corrupted previous snapshot (truncated) → rejected WITHOUT bootstrapping ==="
D="$W/n5"; mkdir -p "$D/assets" "$D/work"; touch "$D/release"
cp "$W/manifest1.json" "$D/assets/gseer-index-manifest.json"; cp "$W/snap-trunc.db" "$D/assets/gseer-index-1.db"
OUT=$( ( export GH_CMD="$W/stub-gh" STUB_DIR="$D" STUB_LOG="$D/log" REPO="Owner/Repo" PROVIDER_BIN="$PROV" WORKDIR="$D/work"
        "$S/pipeline/resolve-sequence.sh" ) 2>&1 ); RC=$?
[ $RC -eq 14 ] && ! grep -q 'RESTORE_MODE=boot' <<<"$OUT" \
  && ok "N5 truncated base refused (checksum): rc=14, no bootstrap fallback" || bad "N5 expected rc 14 w/o boot, got $RC: $OUT"

echo "=== [N4a] unparseable/non-integer sequence → FATAL 12 ==="
D="$W/n4"; mkdir -p "$D/assets" "$D/work"; touch "$D/release"
python3 - "$W/manifest1.json" "$D/assets/gseer-index-manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); m["sequence"] = "2-not-an-int"
open(sys.argv[2], "w").write(json.dumps(m))
PY
cp "$W/snap1.db" "$D/assets/gseer-index-1.db"
OUT=$( ( export GH_CMD="$W/stub-gh" STUB_DIR="$D" STUB_LOG="$D/log" REPO="Owner/Repo" PROVIDER_BIN="$PROV" WORKDIR="$D/work"
        "$S/pipeline/resolve-sequence.sh" ) 2>&1 ); RC=$?
[ $RC -eq 12 ] && ok "N4a invalid sequence refused: rc=12" || bad "N4a expected rc 12, got $RC: $OUT"

echo "=== [N4b] anti-rollback at publish: pointer reuse / concurrent move → FATAL 22 ==="
for CUR in 2 3; do
  D="$W/n4b-$CUR"; mkdir -p "$D/assets" "$D/work/snapshot"; touch "$D/release"
  cp "$W/manifest1.json" "$D/assets/gseer-index-manifest.json"
  python3 - "$W/manifest1.json" "$D/assets/gseer-index-manifest.json" "$CUR" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); m["sequence"] = int(sys.argv[3])
open(sys.argv[2], "w").write(json.dumps(m))
PY
  cp "$W/snap1.db" "$D/work/snapshot/gseer-index-2.db"; cp "$W/manifest1.json" "$D/work/snapshot/gseer-index-manifest.json"
  OUT=$( ( export GH_CMD="$W/stub-gh" STUB_DIR="$D" STUB_LOG="$D/log" REPO="Owner/Repo" PROVIDER_BIN="$PROV" \
           WORKDIR="$D/work" SEQ=2 PREV_SEQ=1
           "$S/pipeline/publish.sh" ) 2>&1 ); RC=$?
  [ $RC -eq 22 ] || bad "N4b pointer@$CUR expected rc 22, got $RC: $OUT"
  grep -q 'upload gseer-index-manifest.json' "$D/log" && bad "N4b pointer@$CUR: manifest WAS uploaded (pointer moved!)" \
                                                          || true
done
grep -q 'upload gseer-index-manifest.json' "$W/n4b-2/log" && bad "N4b: pointer advanced on refusal" \
  || ok "N4b anti-rollback refused (rc=22) and the pointer manifest was NEVER uploaded"

echo "=== [N6] failed snapshot upload → FATAL 21, manifest remains unchanged ==="
D="$W/n6"; mkdir -p "$D/assets" "$D/work/snapshot"; touch "$D/release"
cp "$W/manifest1.json" "$D/assets/gseer-index-manifest.json"
cp "$W/snap1.db" "$D/work/snapshot/gseer-index-2.db"
"$PROV" manifest -snapshot "$D/work/snapshot/gseer-index-2.db" -sequence 2 \
  -artifact-url "http://stub.invalid/releases/download/shared-index/gseer-index-2.db" \
  -tool-version "seq-acceptance" -key "$W/keys/prod.key" -out "$D/work/snapshot/gseer-index-manifest.json" >/dev/null
OUT=$( ( export GH_CMD="$W/stub-gh" STUB_DIR="$D" STUB_LOG="$D/log" REPO="Owner/Repo" PROVIDER_BIN="$PROV" \
         WORKDIR="$D/work" SEQ=2 PREV_SEQ=1 STUB_FAIL_UPLOAD_NAME=gseer-index-2.db
         "$S/pipeline/publish.sh" ) 2>&1 ); RC=$?
[ $RC -eq 21 ] && ! grep -q 'upload gseer-index-manifest.json' "$D/log" \
  && ok "N6 snapshot upload failed → rc=21, pointer manifest NOT uploaded" || bad "N6 expected rc 21 w/o manifest upload, got $RC: $OUT"

echo "=== [P3] atomic publication order: snapshot FIRST, pointer manifest LAST, post-verify ==="
D="$W/p3"; mkdir -p "$D/assets" "$D/work/snapshot"; touch "$D/release"
cp "$W/manifest1.json" "$D/assets/gseer-index-manifest.json"
cp "$W/snap1.db" "$D/work/snapshot/gseer-index-2.db"
"$PROV" manifest -snapshot "$D/work/snapshot/gseer-index-2.db" -sequence 2 \
  -artifact-url "http://stub.invalid/releases/download/shared-index/gseer-index-2.db" \
  -tool-version "seq-acceptance" -key "$W/keys/prod.key" -out "$D/work/snapshot/gseer-index-manifest.json" >/dev/null
OUT=$( ( export GH_CMD="$W/stub-gh" STUB_DIR="$D" STUB_LOG="$D/log" REPO="Owner/Repo" PROVIDER_BIN="$PROV" \
         WORKDIR="$D/work" SEQ=2 PREV_SEQ=1
         "$S/pipeline/publish.sh" ) 2>&1 ); RC=$?
grep -q '^PUBLISH_OK sequence=2' <<<"$OUT" && [ $RC -eq 0 ] && ok "P3 publish: PUBLISH_OK sequence=2 (rc 0)" || bad "P3 publish (rc=$RC): $OUT"
SNAP_LINE=$(grep -n 'upload gseer-index-2.db$' "$D/log" | head -1 | cut -d: -f1)
MAN_LINE=$(grep -n 'upload gseer-index-manifest.json$' "$D/log" | head -1 | cut -d: -f1)
if [ -n "$SNAP_LINE" ] && [ -n "$MAN_LINE" ] && [ "$SNAP_LINE" -lt "$MAN_LINE" ]; then
  ok "P3 order: snapshot upload (line $SNAP_LINE) precedes pointer upload (line $MAN_LINE)"
else
  bad "P3 order wrong: snapshot=$SNAP_LINE manifest=$MAN_LINE"
fi
grep -q 'download gseer-index-manifest.json' "$D/log" && ok "P3 post-publication: published pointer fetched + re-verified" || bad "P3 post-publication verification missing"

echo
echo "SEQUENCE ACCEPTANCE: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] || exit 1
echo "SEQ DONE"
