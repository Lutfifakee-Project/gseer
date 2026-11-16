#!/usr/bin/env bash
# scripts/v032-clean-user-acceptance.sh — CLEAN-USER JOURNEY ACCEPTANCE (target produk).
#
# Alur kriteria owner:
#   INSTALL -> VERIFY VERSION -> SETUP (retrieval + verifikasi shared-index) ->
#   SEARCH -> BANYAK DOMAIN/IP NYATA DENGAN EVIDENCE.
#
# Pemisahan bukti (blocker 3):
#   [LAB]  = publisher pipeline LOKAL (channel loopback).  Koleksi DNS/ip2asn/PTR
#            eksplisit terjadi DI SINI, pada sumber pasif terdokumentasi
#            (Cisco Umbrella Top-1M + resolver publik 1.1.1.1).  Ini BUKAN
#            bagian dari perjalanan clean user dan BUKAN klaim produksi.
#   [USER] = clean client FRESH HOME: hanya setup (unduh + verifikasi Ed25519 +
#            import index) dan search.  TANPA fixture, TANPA seed manual,
#            TANPA perintah collect.  Search terbukti index-only.
#
# Publikasi produksi (release GitHub `shared-index`) TIDAK dilakukan di sini —
# itu tindakan owner.  Clean-client terhadap channel produksi dijalankan owner
# setelah publikasi (perintah tercantum di RELEASE-README).
#
# Env opsional:
#   GSEER_SEEDS_FILE   path CSV slice (rank,domain); default: unduh Umbrella top-1m
#                      dan potong top-250 (URL + sha dicatat ke evidence).
set -uo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

PASS=0; FAIL=0
mark() { if [ "$2" = "0" ]; then echo "  [PASS] $1"; PASS=$((PASS+1)); else echo "  [FAIL] $1"; FAIL=$((FAIL+1)); fi; }
have() { command -v "$1" >/dev/null 2>&1; }

GO=$( [ -n "${GSEER_GO:-}" ] && echo "$GSEER_GO" || { have go && echo go || echo ""; } )
[ -n "$GO" ] || { echo "FATAL: go toolchain required (or set GSEER_GO)" >&2; exit 2; }
export PATH="$(dirname "$(command -v "$GO")"):$PATH"
GOTOOLCHAIN=local

W=$(mktemp -d /tmp/gseer-clean-user.XXXX)
EV="${CLEAN_ACC_LOGDIR:-$W}/evidence"; rm -rf "$EV"; mkdir -p "$EV"
PKG=github.com/Lutfifakee-Project/gseer/internal/index.EmbeddedIndexPublicKeyB64
PORT=$(( 18000 + RANDOM % 2000 ))
URL="http://127.0.0.1:$PORT/gseer-index-manifest.json"
COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# cache modul WAJIB di luar repo (test governance memindai semua .go di bawah repo)
export GOPATH="${GSEER_GOPATH:-$W/gopath}" GOCACHE="${GSEER_GOCACHE:-$W/gocache}"

echo "== GSEER v0.3.2 CLEAN-USER JOURNEY ACCEPTANCE $(date -u +%FT%TZ) =="
echo " baseline commit: $COMMIT"

cleanup() { kill ${SRVPID:-0} 2>/dev/null || true; }
trap 'cleanup' EXIT

echo
echo "== [LAB PIPELINE — publisher side; BUKAN perjalanan clean user] =="

echo "-- seeds: sumber pasif terdokumentasi --"
SEEDS_FILE="${GSEER_SEEDS_FILE:-}"
if [ -z "$SEEDS_FILE" ]; then
  mkdir -p "$W/dataset"
  curl -sSL --max-time 180 -o "$W/dataset/top-1m.csv.zip" \
    "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip" \
    && mark "unduh dataset terpublikasi: Cisco Umbrella Top-1M" $? || mark "unduh dataset Umbrella" 1
  sha256sum "$W/dataset/top-1m.csv.zip" | tee "$EV/dataset-sha256.txt"
  ( cd "$W/dataset" && unzip -q -o top-1m.csv.zip )
  SEEDS_FILE="$W/dataset/top-1m.csv"
fi
SEEDS=$(python3 -c '
import csv,sys
rows=[r[1] for r in csv.reader(open(sys.argv[1]))][:250]
print(",".join(rows))' "$SEEDS_FILE" 2>/dev/null)
NSEEDS=$(echo "$SEEDS" | tr ',' '\n' | grep -c . || true)
[ "${NSEEDS:-0}" -ge 200 ] 2>/dev/null; mark "seeds siap dari dataset terpublikasi (n=$NSEEDS >= 200)" $?

echo "-- build binaries + anchor channel (seremoni produksi, jalur lab) --"
"$GO" build -o "$W/gseer" ./cmd/gseer >/dev/null 2>&1
"$GO" build -o "$W/gseer-provider" ./cmd/gseer-provider >/dev/null 2>&1
"$W/gseer-provider" keygen -pub "$W/index.pub" -priv "$W/index.key" >/dev/null 2>&1
chmod 600 "$W/index.key"
ANCHOR="$(cat "$W/index.pub")"
"$GO" build -ldflags "-X ${PKG}=${ANCHOR}" -o "$W/gseer" ./cmd/gseer >/dev/null 2>&1
"$GO" build -ldflags "-X ${PKG}=${ANCHOR}" -o "$W/gseer-provider" ./cmd/gseer-provider >/dev/null 2>&1
[ -x "$W/gseer" ] && [ -x "$W/gseer-provider" ]; mark "build client + provider dengan trust-anchor channel" $?

echo "-- publisher store + koleksi pasif eksplisit (sisi pipeline) --"
PUB="$W/publisher-home"; mkdir -p "$PUB"
# pola battery resmi: GSEER_HOME *dan* GSEER_CONFIG diunci ke direktori yang sama,
# agar semua subcommand membaca config personal yang sama
export GSEER_HOME="$PUB" GSEER_CONFIG="$PUB/config.yaml"
"$W/gseer" setup --personal --db-path "$PUB/store.db" >/dev/null 2>&1; mark "publisher store (personal mode)" $?
"$W/gseer" source add pipeline-dns --type dns --seeds "$SEEDS" --enable --yes >/dev/null 2>&1
mark "registrasi sumber pipeline-dns (seeds = dataset Umbrella)" $?
"$W/gseer" collect run --source pipeline-dns > "$EV/lab-collect-dns.json" 2>&1
grep -q '"done": true' "$EV/lab-collect-dns.json"; mark "collect DNS eksplisit (publisher; A/AAAA/CNAME/MX/NS atas $NSEEDS domain)" $?
# hitung IP penuh via export (search dibatasi halaman; export streamed) —
# EXPORT DULU, baru ekstraksi seeds enrichment (urutan penting)
"$W/gseer" export 'asset_kind=="ip"' --format json --out "$EV/lab-rows-ip.json" --force >/dev/null 2>&1
NIP_LAB=$(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
rows=d if isinstance(d,list) else d.get("rows",[])
print(len({r["asset_value"] for r in rows}))' "$EV/lab-rows-ip.json" 2>/dev/null || echo 0)
[ "${NIP_LAB:-0}" -ge 100 ] 2>/dev/null; mark "resolver publik mengembalikan IP nyata (n=$NIP_LAB >= 100)" $?
# seeds enrichment: IP dari hasil export store (cap 120 utk argumen CLI)
IPS=$(python3 -c '
import json,sys
d=json.load(open(sys.argv[1]))
rows=d if isinstance(d,list) else d.get("rows",[])
ips=sorted({r["asset_value"] for r in rows if r.get("asset_kind")=="ip"})
print(",".join(ips[:120]))' "$EV/lab-rows-ip.json" 2>/dev/null)
"$W/gseer" source add pipeline-ip2asn --type ip2asn --seeds "$IPS" --resolver 1.1.1.1:53 --enable --yes >/dev/null 2>&1
"$W/gseer" collect run --source pipeline-ip2asn > "$EV/lab-collect-ip2asn.json" 2>&1 || true
grep -q '"done": true' "$EV/lab-collect-ip2asn.json"; mark "enrichment ip2asn pasif (Team Cymru; n=$NIP_LAB IP)" $?
"$W/gseer" source add pipeline-ptr --type ptr --seeds "$IPS" --resolver 1.1.1.1:53 --enable --yes >/dev/null 2>&1
"$W/gseer" collect run --source pipeline-ptr > "$EV/lab-collect-ptr.json" 2>&1 || true
grep -q '"done": true' "$EV/lab-collect-ptr.json"; mark "enrichment PTR pasif (reverse DNS; hostname nyata)" $?

echo "-- snapshot + manifest bertanda tangan + channel lab --"
"$W/gseer-provider" build -store "$PUB/store.db" -out "$W/channel/gseer-index-1.db" >/dev/null 2>&1
mark "gseer-provider build snapshot index" $?
"$W/gseer-provider" manifest -snapshot "$W/channel/gseer-index-1.db" -sequence 1 \
  -artifact-url "http://127.0.0.1:$PORT/gseer-index-1.db" -tool-version "v0.3.2-clean-user-acceptance" \
  -key "$W/index.key" -out "$W/channel/gseer-index-manifest.json" >/dev/null 2>&1
mark "manifest signed (Ed25519, sequence 1)" $?
"$W/gseer-provider" verify -manifest "$W/channel/gseer-index-manifest.json" -artifact "$W/channel/gseer-index-1.db" >/dev/null 2>&1
mark "provider verify fail-closed (signature + checksum)" $?
IDX_ASSETS=$(python3 -c "import json;print(json.load(open('$W/channel/gseer-index-manifest.json'))['counts']['assets'])" 2>/dev/null || echo 0)
IDX_OBS=$(python3 -c "import json;print(json.load(open('$W/channel/gseer-index-manifest.json'))['counts']['observations'])" 2>/dev/null || echo 0)
echo "    manifest counts: assets=$IDX_ASSETS observations=$IDX_OBS"
[ "${IDX_ASSETS:-0}" -ge 300 ] 2>/dev/null; mark "index channel memuat >= 300 aset nyata (actual: $IDX_ASSETS)" $?
( cd "$W/channel" && exec python3 -m http.server "$PORT" --bind 127.0.0.1 >/dev/null 2>&1 ) & SRVPID=$!
sleep 1
curl -fsSL "$URL" -o /dev/null 2>&1; mark "channel lab berjalan (loopback http; http:// hanya loopback)" $?

echo
echo "== [CLEAN USER — fresh home; HANYA setup + search] =="
CH="$W/clean-home"; mkdir -p "$CH"
unset GSEER_HOME GSEER_CONFIG

echo "-- INSTALL --"
# binary clean user: versi rilis + trust-anchor channel (model produksi:
# binary rilis meng-embed public key channel; di lab = keypair lab)
BIN="$W/gseer-release"
"$GO" build -trimpath -ldflags "-X github.com/Lutfifakee-Project/gseer/internal/version.Version=v0.3.2 -X github.com/Lutfifakee-Project/gseer/internal/version.Commit=$COMMIT -X github.com/Lutfifakee-Project/gseer/internal/version.BuiltAt=$TS -X ${PKG}=${ANCHOR}" -o "$BIN" ./cmd/gseer >/dev/null 2>&1
[ -x "$BIN" ]; mark "INSTALL: binary rilis dari source (trimpath + ldflags + trust-anchor channel)" $?

echo "-- VERIFY VERSION --"
VER_OUT=$(HOME="$CH" "$BIN" version 2>&1)
echo "$VER_OUT" | grep -q "v0.3.2"; mark "VERIFY VERSION: gseer version = v0.3.2" $?
if [ "$COMMIT" = "unknown" ]; then
  echo "  [SKIP] commit baseline (tanpa .git)"
else
  echo "$VER_OUT" | grep -q "$COMMIT"; mark "VERIFY VERSION: commit == baseline" $?
fi

echo "-- SETUP: retrieval + verifikasi shared-index (tanpa fixture/seed/collect) --"
SETUP_RC=0
GSEER_INDEX_MANIFEST_URL="$URL" HOME="$CH" "$BIN" setup 2>&1 | tee "$EV/clean-setup-output.txt" || SETUP_RC=$?
SETUP_OUT=$(cat "$EV/clean-setup-output.txt")
[ "$SETUP_RC" = "0" ]; mark "SETUP: selesai tanpa error (rc=0)" $?
echo "$SETUP_OUT" | grep -q 'E_INDEX'; NOIDX=$?; [ "$NOIDX" = "1" ]; mark "SETUP: TANPA E_INDEX (signature/manifest bersih)" $?
echo "$SETUP_OUT" | grep -qiE 'shared index'; mark "SETUP: shared index diterima via channel" $?
IDXSTAT=$(HOME="$CH" "$BIN" search 'asset_kind=="ip"' -o json 2>/dev/null | python3 -c 'import json,sys;d=json.load(sys.stdin);i=d.get("index",{});print(i.get("assets",0),i.get("observations",0))' 2>/dev/null || echo "0 0")
echo "    index client: assets/observations = $IDXSTAT"

echo "-- SEARCH: banyak domain/IP nyata + evidence --"
HOME="$CH" "$BIN" export 'asset_kind=="ip"' --format json --out "$EV/rows-ip.json" --force >/dev/null 2>&1
HOME="$CH" "$BIN" export 'asset_kind=="domain"' --format json --out "$EV/rows-domain.json" --force >/dev/null 2>&1
HOME="$CH" "$BIN" export 'asset_kind=="hostname"' --format json --out "$EV/rows-hostname.json" --force >/dev/null 2>&1
COV=$(python3 - "$EV" <<'PY'
import json, sys, datetime, os
from pathlib import Path
ev = Path(sys.argv[1])
def rows(name):
    f = ev / name
    if not f.exists(): return []
    try:
        d = json.loads(f.read_text())
        return d if isinstance(d, list) else d.get("rows", [])
    except Exception:
        return []
ips, doms, hosts = rows("rows-ip.json"), rows("rows-domain.json"), rows("rows-hostname.json")
uniq_ip = sorted({r.get("asset_value","") for r in ips if r.get("asset_value")})
uniq_dom = sorted({r.get("asset_value","") for r in doms if r.get("asset_value")})
uniq_host = sorted({r.get("asset_value","") for r in hosts if r.get("asset_value")})
allrows = ips + doms + hosts
srcs = sorted({s for r in allrows for s in (r.get("sources") or [])})
now = datetime.datetime.now(datetime.timezone.utc)
def ts(x):
    try: return datetime.datetime.fromisoformat(x.replace("Z","+00:00"))
    except Exception: return None
ages = []
for r in allrows:
    t = ts(r.get("last_seen",""))
    if t: ages.append((now-t).total_seconds())
ages.sort()
fs = sorted(x.get("first_seen") for x in allrows if x.get("first_seen"))
ls = sorted(x.get("last_seen") for x in allrows if x.get("last_seen"))
rep = {
  "unique_ips": len(uniq_ip), "unique_domains": len(uniq_dom), "unique_hostnames": len(uniq_host),
  "total_rows": len(allrows),
  "sources": srcs,
  "first_seen_min": fs[0] if fs else None, "first_seen_max": fs[-1] if fs else None,
  "last_seen_min": ls[0] if ls else None, "last_seen_max": ls[-1] if ls else None,
  "freshness_max_age_sec": ages[-1] if ages else None,
  "freshness_median_age_sec": ages[len(ages)//2] if ages else None,
  "stale_true_rows": sum(1 for r in allrows if r.get("stale")),
  "rows_missing_evidence": sum(1 for r in allrows if not r.get("sources") or not r.get("first_seen") or not r.get("last_seen")),
  "sample_ips": uniq_ip[:10], "sample_domains": uniq_dom[:10], "sample_hostnames": uniq_host[:10],
}
(ev / "search-coverage-report.json").write_text(json.dumps(rep, indent=1))
print(json.dumps(rep))
PY
) || COV="{}"
echo "$COV" | python3 -m json.tool > "$EV/coverage-pretty.txt" 2>/dev/null || true
UIP=$(echo "$COV" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("unique_ips",0))' 2>/dev/null || echo 0)
UDOM=$(echo "$COV" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("unique_domains",0))' 2>/dev/null || echo 0)
UHST=$(echo "$COV" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("unique_hostnames",0))' 2>/dev/null || echo 0)
MISS=$(echo "$COV" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("rows_missing_evidence",0))' 2>/dev/null || echo 1)
STALE=$(echo "$COV" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("stale_true_rows",0))' 2>/dev/null || echo 1)
SRCN=$(echo "$COV" | python3 -c 'import json,sys;print(len(json.load(sys.stdin).get("sources",[])))' 2>/dev/null || echo 0)
echo "    coverage: IP unik=$UIP domain unik=$UDOM hostname unik=$UHST sumber=$SRCN missing_evidence=$MISS stale=$STALE"
[ "${UIP:-0}" -ge 150 ] 2>/dev/null; mark "search: >= 150 IP unik nyata (actual: $UIP)" $?
[ "${UDOM:-0}" -ge 150 ] 2>/dev/null; mark "search: >= 150 domain unik nyata (actual: $UDOM)" $?
[ "${UHST:-0}" -ge 25 ] 2>/dev/null; mark "search: >= 25 hostname unik via PTR (actual: $UHST)" $?
[ "${SRCN:-0}" -ge 2 ] 2>/dev/null; mark "sumber terdokumentasi di tiap baris (actual: $SRCN source)" $?
[ "${MISS:-1}" = "0" ] 2>/dev/null; mark "SEMUA baris membawa evidence (sources+first_seen+last_seen)" $?
[ "${STALE:-1}" = "0" ] 2>/dev/null; mark "freshness: 0 baris stale (data baru dikumpulkan)" $?
HOME="$CH" "$BIN" search 'asset_kind=="domain"' -o table > "$EV/search-domain-table.txt" 2>&1
# laporan coverage versi manusia (blocker 1: jumlah aset unik, sumber, provenance,
# first_seen, last_seen, freshness)
python3 - "$EV/search-coverage-report.json" > "$EV/search-coverage-report.txt" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print("GSEER SEARCH COVERAGE REPORT — clean user, shared-index, tanpa fixture/seed/collect")
print(f"  aset unik         : IP={r['unique_ips']}  domain={r['unique_domains']}  hostname={r['unique_hostnames']}  (total baris {r['total_rows']})")
print(f"  sumber            : {', '.join(r['sources'])}")
print(f"  provenance        : setiap baris membawa 'sources' (L1 identity) + first_seen/last_seen; baris tanpa evidence = {r['rows_missing_evidence']}")
print(f"  first_seen        : {r['first_seen_min']} .. {r['first_seen_max']}")
print(f"  last_seen         : {r['last_seen_min']} .. {r['last_seen_max']}")
print(f"  freshness         : umur maksimum {r['freshness_max_age_sec']:.0f}s, median {r['freshness_median_age_sec']:.0f}s; stale = {r['stale_true_rows']}")
print(f"  contoh IP         : {', '.join(r['sample_ips'][:8])}")
print(f"  contoh domain     : {', '.join(r['sample_domains'][:8])}")
print(f"  contoh hostname   : {', '.join(r['sample_hostnames'][:8])}")
PY
# deep evidence personal-mode: satu aset lengkap via search (gseer host
# belum diwire untuk personal mode — E_PROFILE_UNSUPPORTED; jalur sah: search)
SAMPLE_IP=$(python3 - "$EV/rows-ip.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
rows = d if isinstance(d, list) else d.get("rows", [])
ips = sorted({r["asset_value"] for r in rows if r.get("asset_kind") == "ip"})
print(ips[0] if ips else "")
PY
)
if [ -n "$SAMPLE_IP" ]; then
  HOME="$CH" "$BIN" search "asset_value==\"$SAMPLE_IP\"" -o json > "$EV/deep-evidence-row.json" 2>&1
  HOME="$CH" "$BIN" index status > "$EV/index-status.txt" 2>&1
  { echo "== deep evidence satu aset nyata: $SAMPLE_IP =="; cat "$EV/deep-evidence-row.json"; echo; echo "== gseer index status =="; cat "$EV/index-status.txt"; } > "$EV/host-deep-evidence.txt"
  python3 - "$EV/deep-evidence-row.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
rows = d if isinstance(d, list) else d.get("rows", [])
r = rows[0] if rows else {}
need = ["asset_value", "sources", "first_seen", "last_seen", "stale"]
sys.exit(0 if all(k in r for k in need) else 1)
PY
  mark "deep evidence satu aset (search: sources/first_seen/last_seen/stale + index status) — $SAMPLE_IP" $?
else
  mark "deep evidence satu aset (search)" 1
fi

echo "-- NO-DISCOVERY: search hanya membaca index --"
BEFORE=$(HOME="$CH" "$BIN" export 'asset_kind=="domain"' --format json --out "$W/before.json" --force >/dev/null 2>&1; python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));r=d if isinstance(d,list) else d.get("rows",[]);print(len(r))' "$W/before.json" 2>/dev/null || echo 0)
HOME="$CH" "$BIN" search 'domain CONTAINS "totally-not-in-index-xyz"' >/dev/null 2>&1
HOME="$CH" "$BIN" search 'asset_kind=="domain"' >/dev/null 2>&1
HOME="$CH" "$BIN" export 'asset_kind=="domain"' --format json --out "$W/after.json" --force >/dev/null 2>&1
AFTER=$(python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));r=d if isinstance(d,list) else d.get("rows",[]);print(len(r))' "$W/after.json" 2>/dev/null || echo 0)
[ "$BEFORE" = "$AFTER" ]; mark "search tidak menambah aset ($BEFORE -> $AFTER)" $?
VIOL=$(grep -rl '"internal/collect"\|"internal/observe"\|"internal/scan"' internal/index/*.go 2>/dev/null | grep -c . || true)
[ "${VIOL:-1}" = "0" ] 2>/dev/null; mark "statik: paket query tidak mengimpor collect/observe/scan" $?
HOME="$CH" "$BIN" scan http --target example.com --port 443 >/dev/null 2>&1
[ $? -ne 0 ]; mark "scan tanpa scope ditolak fail-closed (guardrail aktif)" $?

echo
echo "== HASIL =="
echo " PASSED: $PASS  FAILED: $FAIL"
[ "$FAIL" = "0" ] && echo " CLEAN-USER ACCEPTANCE: PASS" || echo " CLEAN-USER ACCEPTANCE: FAIL"
cp -f "$EV/search-coverage-report.json" "${CLEAN_ACC_LOGDIR:-/tmp}/clean-coverage.json" 2>/dev/null || true
chmod -R u+w "$W" 2>/dev/null; rm -rf "$W" 2>/dev/null
[ "$FAIL" = "0" ]
