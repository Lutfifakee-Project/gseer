#!/usr/bin/env bash
# GSEER v0.3.2 ASDLC — CUMULATIVE SHARED-INDEX ACCEPTANCE.
#
# Proves the cumulative publication model of .github/workflows/index.yml
# end-to-end on a local durable channel (http.server loopback), using
# REAL internet data (owner zone DNS + Team Cymru/Cloudflare resolvers):
#
#   P1  local channel keypair + anchor-injected builds (production ceremony)
#   P2  sequence 1: fresh pipeline store → real DNS collect → AUTHORIZED
#       loopback lab observation → build → manifest(seq 1) → verify → publish
#   P3  sequence 2 runner (mirrors index.yml): download prev manifest+artifact
#       → gseer-provider verify (signature + checksum, fail-closed) → restore
#       as the working store → incremental collect → build → manifest(seq 2)
#       → verify → publish; counts must be ≥ sequence 1
#   P4  PERSISTENCE: a fact observed ONLY in sequence 1 (the lab service,
#       NOT re-scanned in sequence 2) must still be in the sequence-2
#       snapshot and findable by a FRESH client after one import
#   P5  DEDUP: a client that imported sequence 1 runs `index update`
#       → sequence 2 installs and imports idempotently (deduped > 0)
#   P6  FAIL-CLOSED: a tampered base artifact is REFUSED by the restore
#       verification (checksum)
#   P7  FAIL-CLOSED: a foreign-key base is REFUSED (bad signature)
#
# Honesty rules: no fabricated rows; the lab target is explicitly labeled;
# the owner-zone DNS data is real internet data; every assertion echoes its
# actual output.  Private key material never enters any transcript.
set -uo pipefail
S=/home/z/my-project/work/remediation/gseer-v032-remediation/source
EV=/home/z/my-project/work/remediation/evidence
W=/tmp/asdlc-cum
PORT=18601
PKG=github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64
URL="http://127.0.0.1:$PORT/gseer-index-manifest.json"
export PATH=/home/z/my-project/tools/go/bin:$PATH GOPATH=/home/z/my-project/tools/gopath \
       GOMODCACHE=/home/z/my-project/tools/gopath/pkg/mod GOCACHE=/home/z/my-project/tools/gocache \
       GOTOOLCHAIN=local

rm -rf "$W"; mkdir -p "$W/channel" "$EV"
PASS=0; FAIL=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
die()  { echo "!!! CUM-FAIL: $*"; exit 1; }
cleanup() { kill ${SRVPID:-0} ${LABPID:-0} 2>/dev/null || true; }
trap 'cleanup; exit' EXIT

echo "=== [P1] local channel keypair + anchor-injected builds (production ceremony) ==="
cd "$S" || die "no source tree"
go build -o "$W/gseer" ./cmd/gseer          || die "client build"
go build -o "$W/gseer-provider" ./cmd/gseer-provider || die "provider build"
"$W/gseer-provider" keygen -pub "$W/index.pub" -priv "$W/index.key" >/dev/null || die "keygen"
chmod 600 "$W/index.key"
ANCHOR="$(cat "$W/index.pub")"
go build -ldflags "-X ${PKG}=${ANCHOR}" -o "$W/gseer" ./cmd/gseer          || die "anchor client build"
go build -ldflags "-X ${PKG}=${ANCHOR}" -o "$W/gseer-provider" ./cmd/gseer-provider || die "anchor provider build"
ok "P1 binaries built with the channel anchor injected (ldflags)"

echo
echo "=== [P2] sequence 1: fresh pipeline store + REAL DNS + authorized lab observation ==="
LABDIR="$W/lab"; mkdir -p "$LABDIR"
cat > "$LABDIR/server.py" <<'PY'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0 (cumulative-acceptance-lab)"
    sys_version = ""
    def do_GET(self):
        body = b"<html><head><title>CUMSEQ1 Lab Target</title></head><body>authorized loopback lab target</body></html>"
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.4", 8443), H) as s:
    s.serve_forever()
PY
python3 "$LABDIR/server.py" & LABPID=$!
sleep 0.6

export GSEER_HOME="$W/run1/home" GSEER_CONFIG="$W/run1/home/config.yaml"
"$W/gseer" setup --personal --db-path "$W/run1/home/store.db" >/dev/null || die "seq1 pipeline setup"
"$W/gseer" source add pipeline-dns --type dns --seeds "lutfifakee.top" --enable --yes >/dev/null || die "seq1 source add"
"$W/gseer" collect run --source pipeline-dns 2>&1 | tee "$EV/rem-cum-seq1-dns.txt" | grep '"records"' | head -1
IPS=$("$W/gseer" search 'asset_kind == "ip"' --output json 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(r["asset_value"] for r in d["rows"]))' || true)
[ -n "$IPS" ] || die "seq1 produced no IPs (DNS availability)"
echo "  seq1 discovered owner IPs: $IPS"
"$W/gseer" source add pipeline-ip2asn --type ip2asn --seeds "$IPS" --resolver 1.1.1.1:53 --enable --yes >/dev/null
"$W/gseer" collect run --source pipeline-ip2asn >/dev/null 2>&1 || true
"$W/gseer" source add pipeline-ptr --type ptr --seeds "$IPS" --resolver 1.1.1.1:53 --enable --yes >/dev/null
"$W/gseer" collect run --source pipeline-ptr >/dev/null 2>&1 || true
"$W/gseer" scope add cidr 127.0.0.4/32 --protocols http --ports 8443 --note "cumulative-acceptance authorized lab target" >/dev/null
"$W/gseer" scan http --target 127.0.0.4 --port 8443 2>&1 | tee "$EV/rem-cum-seq1-scan.txt" | tail -2
kill $LABPID 2>/dev/null; LABPID=0
"$W/gseer-provider" build -store "$W/run1/home/store.db" -out "$W/channel/gseer-index-1.db" >/dev/null || die "seq1 build"
"$W/gseer-provider" manifest -snapshot "$W/channel/gseer-index-1.db" -sequence 1 \
  -artifact-url "http://127.0.0.1:$PORT/gseer-index-1.db" -tool-version "v0.3.2-rem-acceptance" \
  -key "$W/index.key" -out "$W/channel/gseer-index-manifest.json" >/dev/null || die "seq1 manifest"
"$W/gseer-provider" verify -manifest "$W/channel/gseer-index-manifest.json" -artifact "$W/channel/gseer-index-1.db" >/dev/null \
  || die "seq1 pre-publish verify"
SEQ1_ASSETS=$(python3 -c "import json;print(json.load(open('$W/channel/gseer-index-manifest.json'))['counts']['assets'])")
SEQ1_OBS=$(python3 -c "import json;print(json.load(open('$W/channel/gseer-index-manifest.json'))['counts']['observations'])")
echo "  sequence 1 published: assets=$SEQ1_ASSETS observations=$SEQ1_OBS"
ok "P2 sequence 1 built, signed, verified, published"

echo
echo "=== [P3] sequence 2 runner — mirrors index.yml: resolve → verify base → restore → incremental collect ==="
mkdir -p "$W/release-seq1"
cp "$W/channel/gseer-index-1.db" "$W/channel/gseer-index-manifest.json" "$W/release-seq1/"

python3 - "$W/release-seq1/gseer-index-1.db" "$W/tampered.db" <<'PY'
import sys
b = bytearray(open(sys.argv[1], "rb").read())
b[len(b)//2] ^= 0xFF
open(sys.argv[2], "wb").write(b)
PY
if "$W/gseer-provider" verify -manifest "$W/release-seq1/gseer-index-manifest.json" -artifact "$W/tampered.db" >/tmp/cum-tamper.txt 2>&1; then
  bad "P6 tampered base ACCEPTED (must be refused)"
else
  echo "    refused: $(grep -m1 'E_INDEX\|checksum' /tmp/cum-tamper.txt | tail -1)"
  ok "P6 tampered base refused (checksum, fail-closed)"
fi

"$W/gseer-provider" keygen -pub "$W/foreign.pub" -priv "$W/foreign.key" >/dev/null
"$W/gseer-provider" manifest -snapshot "$W/release-seq1/gseer-index-1.db" -sequence 2 \
  -artifact-url "http://127.0.0.1:$PORT/gseer-index-1.db" -tool-version "attacker" \
  -key "$W/foreign.key" -out "$W/foreign-manifest.json" >/dev/null
if "$W/gseer-provider" verify -manifest "$W/foreign-manifest.json" -artifact "$W/release-seq1/gseer-index-1.db" >/tmp/cum-foreign.txt 2>&1; then
  bad "P7 foreign-key manifest ACCEPTED (must be refused)"
else
  echo "    refused: $(grep -m1 'E_INDEX' /tmp/cum-foreign.txt | tail -1)"
  ok "P7 foreign-key base refused (signature, fail-closed)"
fi

"$W/gseer-provider" verify -manifest "$W/release-seq1/gseer-index-manifest.json" \
                           -artifact "$W/release-seq1/gseer-index-1.db" >/dev/null || die "seq2 base verify"
"$W/gseer-provider" inspect -snapshot "$W/release-seq1/gseer-index-1.db" \
                            -manifest "$W/release-seq1/gseer-index-manifest.json" >/dev/null || die "seq2 base inspect"
export GSEER_HOME="$W/run2/home" GSEER_CONFIG="$W/run2/home/config.yaml"
mkdir -p "$GSEER_HOME"
cp "$W/release-seq1/gseer-index-1.db" "$GSEER_HOME/store.db"
chmod 600 "$GSEER_HOME/store.db"
"$W/gseer" setup --personal --db-path "$GSEER_HOME/store.db" >/dev/null || die "seq2 setup on restored store"
echo "  base restored: sequence-1 facts are the working store (provenance intact)"
"$W/gseer" source add pipeline-dns --type dns --seeds "lutfifakee.top" --enable --yes >/dev/null || die "seq2 source add (EnsureSource upsert)"
"$W/gseer" collect run --source pipeline-dns >/dev/null 2>&1 || die "seq2 DNS collect"
IPS2=$("$W/gseer" search 'asset_kind == "ip"' --output json 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(r["asset_value"] for r in d["rows"]))' || true)
if [ -n "$IPS2" ]; then
  "$W/gseer" source add pipeline-ip2asn --type ip2asn --seeds "$IPS2" --resolver 1.1.1.1:53 --enable --yes >/dev/null
  "$W/gseer" collect run --source pipeline-ip2asn >/dev/null 2>&1 || true
  "$W/gseer" source add pipeline-ptr --type ptr --seeds "$IPS2" --resolver 1.1.1.1:53 --enable --yes >/dev/null
  "$W/gseer" collect run --source pipeline-ptr >/dev/null 2>&1 || true
fi
"$W/gseer-provider" build -store "$GSEER_HOME/store.db" -out "$W/channel/gseer-index-2.db" >/dev/null || die "seq2 build"
"$W/gseer-provider" manifest -snapshot "$W/channel/gseer-index-2.db" -sequence 2 \
  -artifact-url "http://127.0.0.1:$PORT/gseer-index-2.db" -tool-version "v0.3.2-rem-acceptance" \
  -key "$W/index.key" -out "$W/channel/gseer-index-manifest.json" >/dev/null || die "seq2 manifest"
"$W/gseer-provider" verify -manifest "$W/channel/gseer-index-manifest.json" -artifact "$W/channel/gseer-index-2.db" >/dev/null \
  || die "seq2 pre-publish verify"
cp "$W/channel/gseer-index-manifest.json" "$W/seq2-manifest.json"
SEQ2_ASSETS=$(python3 -c "import json;print(json.load(open('$W/channel/gseer-index-manifest.json'))['counts']['assets'])")
SEQ2_OBS=$(python3 -c "import json;print(json.load(open('$W/channel/gseer-index-manifest.json'))['counts']['observations'])")
echo "  sequence 2 published: assets=$SEQ2_ASSETS observations=$SEQ2_OBS (sequence 1: assets=$SEQ1_ASSETS obs=$SEQ1_OBS)"
if [ "$SEQ2_ASSETS" -ge "$SEQ1_ASSETS" ]; then ok "P3 cumulative counts: seq2 assets ($SEQ2_ASSETS) ≥ seq1 ($SEQ1_ASSETS)"
else bad "P3 seq2 assets ($SEQ2_ASSETS) < seq1 ($SEQ1_ASSETS) — coverage was erased"; fi

echo
echo "=== [P4] PERSISTENCE: the seq1-only lab fact must survive into seq2 (fresh client) ==="
unset GSEER_HOME GSEER_CONFIG
( cd "$W/channel" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) & SRVPID=$!
sleep 0.8
curl -fsSL "$URL" -o /dev/null || die "channel unreachable"
CH="$W/client-home"; mkdir -p "$CH"
GSEER_INDEX_MANIFEST_URL="$URL" HOME="$CH" "$W/gseer" setup 2>&1 | tee "$EV/rem-cum-client-setup.txt" | grep -E 'shared index|imported' | sed 's/^/    /'
FOUND=$(HOME="$CH" "$W/gseer" search 'title="CUMSEQ1 Lab Target"' --output json 2>/dev/null \
  | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("rows",[])))')
if [ "${FOUND:-0}" -ge 1 ]; then ok "P4 seq1-only observation found in the seq2 snapshot by a fresh client ($FOUND row(s))"
else bad "P4 seq1-only observation MISSING from the seq2 snapshot — cumulative restore failed"; fi

echo
echo "=== [P4b] clean-machine acceptance: gseer status reports verified + installed ==="
ST=$(HOME="$CH" "$W/gseer" status 2>&1); echo "$ST" | sed 's/^/    /' | head -10
if echo "$ST" | grep -q 'verified + installed sequence'; then
  ok "P4b gseer status reports the shared index VERIFIED + INSTALLED"
else
  bad "P4b gseer status missing the verified+installed report"
fi

echo
echo "=== [P5] DEDUP: client imported seq1 → index update → seq2 (idempotent incremental import) ==="
cp "$W/release-seq1/gseer-index-manifest.json" "$W/channel/gseer-index-manifest.json"
CH5="$W/client-home-seq1"; mkdir -p "$CH5"
GSEER_INDEX_MANIFEST_URL="$URL" HOME="$CH5" "$W/gseer" setup >/dev/null 2>&1 || die "client setup at seq1"
cp "$W/seq2-manifest.json" "$W/channel/gseer-index-manifest.json"
UP=$(HOME="$CH5" "$W/gseer" index update --manifest-url "$URL" 2>&1) || die "client index update seq1→seq2"
echo "$UP" | sed 's/^/    /'
echo "$UP" | grep -q 'manifest verified (signature, sequence 2,' && echo "$UP" | grep -q 'installed atomically' \
  && ok "P5 update verified sequence 2 and installed it atomically over sequence 1" \
  || bad "P5 update did not install sequence 2"
DEDUP=$(echo "$UP" | grep -o '[0-9]* deduped' | grep -o '^[0-9]*')
if [ "${DEDUP:-0}" -ge 1 ]; then ok "P5 incremental import deduped $DEDUP observation(s) already known from seq1"
else bad "P5 no dedup reported — the import was not idempotent"; fi

echo
echo "=== [P6b] real-data search: the port field executes on the imported shared index (no URL, no seeds, no manual DB) ==="
HOME="$CH" "$W/gseer" search 'port=443' >/tmp/p443.txt 2>&1; RC443=$?
# The canonical UX command must EXECUTE cleanly against the imported index.
# An honest EMPTY is the correct result here: this lab run has no 443 service
# (local binds <1024 are denied in the sandbox) and fabricating one is forbidden.
if [ $RC443 -eq 0 ]; then
  ok "P6b-i 'port=443' executes cleanly on the imported shared index (rc 0; honest result, no fabricated rows)"
else
  bad "P6b-i 'port=443' failed (rc=$RC443): $(tail -2 /tmp/p443.txt)"
fi
R8443=$(HOME="$CH" "$W/gseer" search 'port=8443' --output json 2>/dev/null \
  | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("rows",[])))')
if [ "${R8443:-0}" -ge 1 ]; then
  ok "P6b-ii the port field returns real evidenced rows from the imported index (port=8443 lab service: $R8443 row(s))"
else
  bad "P6b-ii no rows for port=8443 — the port execution path failed"
fi

kill $SRVPID 2>/dev/null; SRVPID=0
echo
echo "CUMULATIVE ACCEPTANCE: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ] || exit 1
echo "CUM DONE"
