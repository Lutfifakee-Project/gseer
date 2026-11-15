#!/usr/bin/env bash
# GSEER v0.3.2 REMEDIATION — PRODUCTION TRUST-ANCHOR ACCEPTANCE.
#
# Verifies the complete production trust chain end-to-end with REAL
# release-candidate builds (mandatory remediation §3):
#
#   A1  release-candidate build via the EXACT .goreleaser.yaml ldflags
#       (trimpath, buildvcs=false, -s -w, version metadata, anchor -X)
#       with a stand-in "production" key → the anchor is embedded in
#       the released CLI binary (grep -a, never echoed);
#   A2  pipeline-style build (index.yml ldflags) → the anchor is
#       embedded in BOTH gseer and gseer-provider;
#   A3  the release.yml verification gate (find dist + grep -a) PASSES
#       for anchored binaries and FAILS for a binary built WITHOUT the
#       injection (the in-repo TEST anchor would otherwise silently
#       become the production trust anchor);
#   N7  a manifest signed by the TEST key is REJECTED by a
#       production-anchored binary (E_INDEX_BAD_SIGNATURE), while a
#       manifest signed by the matching production key verifies.
set -uo pipefail
S=/home/z/my-project/work/remediation/gseer-v032-remediation/source
W=/tmp/asdlc-anchor
export PATH=/home/z/my-project/tools/go/bin:$PATH GOPATH=/home/z/my-project/tools/gopath \
       GOMODCACHE=/home/z/my-project/tools/gopath/pkg/mod GOCACHE=/home/z/my-project/tools/gocache \
       GOTOOLCHAIN=local

PASS=0; FAIL=0
ok()  { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
die() { echo "!!! ANCHOR-FAIL: $*"; exit 1; }

rm -rf "$W"; mkdir -p "$W/keys" "$W/dist" "$W/build"
cd "$S" || die "no source tree"

go build -o "$W/gseer-provider" ./cmd/gseer-provider || die "provider build"
"$W/gseer-provider" keygen -pub "$W/keys/prod.pub" -priv "$W/keys/prod.key" >/dev/null
"$W/gseer-provider" keygen -pub "$W/keys/test.pub" -priv "$W/keys/test.key" >/dev/null
chmod 600 "$W/keys/"*.key
PROD_PUB="$(cat "$W/keys/prod.pub")"
TEST_PUB="$(cat "$W/keys/test.pub")"

echo "=== [A1] release-candidate build via the EXACT .goreleaser.yaml ldflags ==="
VERSION="v0.3.2-rc" COMMIT="0000000000000000000000000000000000000000" DATE="2026-11-15T00:00:00Z"
go build -trimpath -buildvcs=false -ldflags "-s -w \
  -X github.com/Lutfifakee-Project/gseer/internal/version.Version=$VERSION \
  -X github.com/Lutfifakee-Project/gseer/internal/version.Commit=$COMMIT \
  -X github.com/Lutfifakee-Project/gseer/internal/version.BuiltAt=$DATE \
  -X github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64=$PROD_PUB" \
  -o "$W/dist/gseer" ./cmd/gseer || die "release-candidate build"
if grep -aqF -- "$PROD_PUB" "$W/dist/gseer"; then ok "A1 released CLI embeds the production anchor"
else bad "A1 released CLI does NOT embed the production anchor"; fi

echo "=== [A2] pipeline build (index.yml ldflags) → anchor in BOTH binaries ==="
go build -ldflags "-X github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64=$PROD_PUB" \
  -o "$W/build/gseer" ./cmd/gseer || die "pipeline client build"
go build -ldflags "-X github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64=$PROD_PUB" \
  -o "$W/build/gseer-provider" ./cmd/gseer-provider || die "pipeline provider build"
A2=1
for B in "$W/build/gseer" "$W/build/gseer-provider"; do
  if grep -aqF -- "$PROD_PUB" "$B"; then echo "    [ok] anchor embedded: $B"; else bad "A2 anchor missing: $B"; A2=0; fi
done
[ $A2 -eq 1 ] && ok "A2 pipeline CLI + provider both embed the production anchor"

echo "=== [A3] the release.yml verification gate: PASS anchored, FAIL unanchored ==="
verify_gate() {  # exactly the release.yml step logic
  local pub="$1" dir="$2" n=0 f
  while IFS= read -r -d '' f; do
    if grep -aqF -- "$pub" "$f"; then n=$((n+1)); else echo "MISSING: $f"; return 1; fi
  done < <(find "$dir" -type f -name 'gseer' -print0)
  [ "$n" -ge 1 ]
}
if verify_gate "$PROD_PUB" "$W/dist"; then ok "A3 gate PASSES for the anchored release candidate"
else bad "A3 gate failed on an anchored binary"; fi
go build -o "$W/dist-unanchored/gseer" ./cmd/gseer || die "unanchored build"   # default = in-repo TEST anchor
if verify_gate "$PROD_PUB" "$W/dist-unanchored"; then bad "A3 gate FAILED to catch an unanchored (test-anchor) binary"
else ok "A3 gate REFUSES a binary built without the production injection (test anchor cannot silently ship)"; fi

echo "=== [N7] test-key manifest REJECTED by production-anchored binaries ==="
STORE="$W/store.db"
"$W/build/gseer" setup --personal --db-path "$STORE" >/dev/null || die "store setup"
"$W/build/gseer-provider" build -store "$STORE" -out "$W/snap.db" >/dev/null || die "snapshot build"
"$W/gseer-provider" manifest -snapshot "$W/snap.db" -sequence 1 \
  -artifact-url "http://127.0.0.1:9/gseer-index-1.db" -tool-version "anchor-acceptance" \
  -key "$W/keys/test.key" -out "$W/manifest-test.json" >/dev/null
"$W/gseer-provider" manifest -snapshot "$W/snap.db" -sequence 1 \
  -artifact-url "http://127.0.0.1:9/gseer-index-1.db" -tool-version "anchor-acceptance" \
  -key "$W/keys/prod.key" -out "$W/manifest-prod.json" >/dev/null
if "$W/build/gseer-provider" verify -manifest "$W/manifest-test.json" >/tmp/anchor-n7.txt 2>&1; then
  bad "N7 TEST-key manifest ACCEPTED by production-anchored provider (must be refused)"
else
  echo "    refused: $(grep -m1 'E_INDEX' /tmp/anchor-n7.txt)"
  ok "N7 TEST-key manifest REJECTED by the production-anchored provider"
fi
if "$W/build/gseer-provider" verify -manifest "$W/manifest-prod.json" >/tmp/anchor-p7.txt 2>&1; then
  ok "N7 production-key manifest VERIFIED (signature VALID, sequence 1)"
else
  bad "N7 production-key manifest rejected (verify broken): $(cat /tmp/anchor-p7.txt)"
fi

echo
echo "ANCHOR ACCEPTANCE: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] || exit 1
echo "ANCHOR DONE"
