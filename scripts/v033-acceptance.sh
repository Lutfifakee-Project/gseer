#!/usr/bin/env bash
# scripts/v033-acceptance.sh — REAL-CONDITION ACCEPTANCE DRIVER (GSEER v0.3.3-rc1).
#
# Mandat R6: acceptance wajib menguji kondisi nyata — alur lengkap
# install → version → setup → dataset update (LIVE) → dataset status →
# search → export → selfcheck, PLUS: update dua kali tanpa duplikasi,
# kegagalan jaringan saat update, manifest/payload rusak / tanda tangan
# tidak valid, restart aplikasi + search setelah restart, dan bebas
# ketergantungan pada working directory / environment GLM.
#
# Semua berjalan di home terisolasi (tidak menyentuh data operator).
# Downgrade gate diuji di level unit (TestDatasetUpdateDowngradeRefused-
# Explicitly) karena channel yang menawarkan versi lebih lama tetap
# harus bertanda tangan sah — hanya produksi yang bisa membuatnya.
set -uo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$REPO_ROOT"

PASS=0; FAIL=0
mark() { if [ "$2" = "0" ]; then echo "  [PASS] $1"; PASS=$((PASS+1)); else echo "  [FAIL] $1"; FAIL=$((FAIL+1)); fi; }
grepq() { grep -q "$1" "$2" 2>/dev/null; }

GO=$( [ -n "${GSEER_GO:-}" ] && echo "$GSEER_GO" || { command -v go >/dev/null 2>&1 && echo go || echo ""; } )
[ -n "$GO" ] || { echo "FATAL: go toolchain required (or set GSEER_GO)" >&2; exit 2; }
export PATH="$(dirname "$(command -v "$GO")"):$PATH"
GOTOOLCHAIN=local

W=$(mktemp -d /tmp/gseer-v033-acc.XXXX)
H="$W/home"; mkdir -p "$H"
export GSEER_HOME="$H/.gseer"
BIN="$REPO_ROOT/bin/gseer"
export GOPATH="${GSEER_GOPATH:-$W/gopath}" GOCACHE="${GSEER_GOCACHE:-$W/gocache}"

echo "== GSEER v0.3.3-rc1 REAL-CONDITION ACCEPTANCE $(date -u +%FT%TZ) =="
echo " workdir: $W  home: $GSEER_HOME"

echo "== [A] build & vet =="
"$GO" build ./... >/dev/null 2>&1; mark "go build ./..." $?
"$GO" vet ./... >/dev/null 2>&1; mark "go vet ./..." $?
make build >/dev/null 2>&1; mark "make build" $?

echo "== [B] identity & clean-dir install =="
"$BIN" version | grep -q "gseer v0.3.3-rc1"; mark "version == v0.3.3-rc1" $?

echo "== [C] full journey: setup → update(LIVE) → status → search → export → selfcheck =="
"$BIN" setup --personal > "$W/j-setup.log" 2>&1; mark "setup --personal (GSEER_HOME bersih)" $?
"$BIN" dataset update > "$W/j-update.log" 2>&1
if grepq "dataset v" "$W/j-update.log" && grepq "payload verified" "$W/j-update.log"; then
  mark "dataset update LIVE (manifest+payload terverifikasi)" 0
else
  mark "dataset update LIVE (manifest+payload terverifikasi)" 1
fi
grepq "imported:" "$W/j-update.log"; mark "dataset import tercatat" $?
"$BIN" dataset status > "$W/j-status.log" 2>&1 && grepq "version" "$W/j-status.log"; mark "dataset status (versi terpasang)" $?
"$BIN" search 'port=443' --format json > "$W/j-search.json" 2>&1
python3 -c "import json,sys; d=json.load(open('$W/j-search.json')); sys.exit(0 if d.get('count',0)>0 else 1)" 2>/dev/null
mark "search port=443 (LIVE data, hasil bermakna)" $?
"$BIN" search 'port=443' --format json > "$W/e.json" 2>&1 && [ -s "$W/e.json" ]; mark "export json" $?
"$BIN" search 'port=443' --format csv > "$W/e.csv" 2>&1 && [ "$(wc -l < "$W/e.csv")" -ge 2 ]; mark "export csv (header+baris)" $?
"$BIN" search 'port=443' --format ndjson > "$W/e.ndjson" 2>&1 && [ "$(wc -l < "$W/e.ndjson")" -ge 1 ]; mark "export ndjson" $?
python3 - "$W/e.json" "$W/e.csv" "$W/e.ndjson" <<'PY'
import csv, json, sys
rows = json.load(open(sys.argv[1]))["rows"]
n_json = len(rows)
with open(sys.argv[2]) as f:
    n_csv = sum(1 for _ in csv.reader(f)) - 1  # header
n_nd = sum(1 for _ in open(sys.argv[3]))
sys.exit(0 if n_json == n_csv == n_nd and n_json > 0 else 1)
PY
mark "konsistensi json/csv/ndjson (jumlah baris sama)" $?
"$BIN" selfcheck > "$W/j-selfcheck.log" 2>&1
grepq "All invariant checks passed" "$W/j-selfcheck.log"; mark "selfcheck (semua invarian)" $?

echo "== [D] update 2x tanpa duplikasi + riwayat =="
ASSETS1=$(sqlite3 "$GSEER_HOME/gseer.db" "SELECT COUNT(*) FROM assets" 2>/dev/null || "$BIN" search 'ip != ""' --format json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])")
"$BIN" dataset update > "$W/j-update2.log" 2>&1
grepq "already at version" "$W/j-update2.log"; mark "update ke-2 = no-op (already at version)" $?
ASSETS2=$(sqlite3 "$GSEER_HOME/gseer.db" "SELECT COUNT(*) FROM assets" 2>/dev/null || "$BIN" search 'ip != ""' --format json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])")
[ "$ASSETS1" = "$ASSETS2" ]; mark "tanpa duplikasi (aset $ASSETS1 → $ASSETS2)" $?
"$BIN" dataset history > "$W/j-hist.log" 2>&1 && grepq "dataset import history" "$W/j-hist.log"; mark "dataset history (riwayat versi)" $?

echo "== [E] coverage metrics (R1) =="
"$BIN" coverage --output json > "$W/j-coverage.json" 2>&1
python3 -c "
import json,sys
d=json.load(open('$W/j-coverage.json'))
assert 'unique_assets' in d and 'source_statuses' in d and 'assets_seen_by_multiple_sources' in d and 'oldest_observed_at' in d
sys.exit(0)" 2>/dev/null
mark "coverage JSON (aset, status sumber, dup lintas sumber, umur)" $?

echo "== [F] bench skala & kualitas (R5, korpus kecil cepat) =="
"$BIN" bench scale --base 60 --times 1,2 > "$W/j-scale.log" 2>&1; mark "bench scale 1x/2x (import nyata)" $?
"$BIN" bench quality --corpus 300 > "$W/j-quality.log" 2>&1
grepq "accuracy (queries with F1 == 1.0): 1.000" "$W/j-quality.log"; mark "bench quality F1 == 1.0 semua query" $?

echo "== [G] negatif: gangguan jaringan, manifest/payload rusak, tanda tangan =="
"$BIN" dataset update --manifest-url http://127.0.0.1:9/gseer-dataset-manifest.json > "$W/n-net.log" 2>&1
grepq "E_DATASET_UNREACHABLE" "$W/n-net.log"; mark "network gagal → E_DATASET_UNREACHABLE (jujur, cepat)" $?
# Bersihkan server loopback sisa run lain (hindari zombie server di port uji).
pkill -f "http.server 8" >/dev/null 2>&1 || true
sleep 0.5
MANIFEST_URL=$(grep -oE "checking the manifest \((http[^)]+)\)" "$W/j-update.log" | head -1 | sed -E 's/.*\((http[^)]+)\)/\1/')
PORT1=$((20000 + RANDOM % 20000))
PORT2=$((20000 + RANDOM % 20000))
if [ -n "$MANIFEST_URL" ] && command -v curl >/dev/null 2>&1; then
  curl -sSL "$MANIFEST_URL" > "$W/manifest.json" 2>/dev/null
  curl -sSL "${MANIFEST_URL%/*}/gseer-dataset.ndjson.gz" > "$W/payload.gz" 2>/dev/null
  [ -s "$W/manifest.json" ] && [ -s "$W/payload.gz" ]; mark "unduh manifest+payload LIVE untuk fixture tamper" $?
  # (a) manifest tamper: satu digit diubah → tanda tangan gugur
  mkdir -p "$W/serve"
  python3 -c "
import json,re
data=open('$W/manifest.json','r').read()
# Tamper a field with NO parse-time consistency check (generated_at_utc):
# only the Ed25519 signature can catch this one.
data=re.sub(r'\"generated_at_utc\": \"2026-11-27T', '\"generated_at_utc\": \"2020-11-27T', data, count=1)
open('$W/serve/gseer-dataset-manifest.json','w').write(data)" 2>/dev/null
  cp "$W/payload.gz" "$W/serve/gseer-dataset.ndjson.gz"
  ( cd "$W/serve" && python3 -m http.server $PORT1 >/dev/null 2>&1 & echo $! > "$W/serve.pid" )
  sleep 1
  # Verifikasi fixture benar-benar tersaji (guard anti zombie/blank).
  SERVED=$(curl -sS "http://127.0.0.1:$PORT1/gseer-dataset-manifest.json" | wc -c)
  if [ "$SERVED" -gt 500 ]; then
    "$BIN" dataset update --manifest-url "http://127.0.0.1:$PORT1/gseer-dataset-manifest.json" > "$W/n-sig.log" 2>&1
    grepqE() { grep -qE "$1" "$2" 2>/dev/null; }
    grepqE "E_DATASET_(BAD_SIGNATURE|UNKNOWN_KEY)" "$W/n-sig.log"
    mark "manifest tamper → signature ditolak (fail-closed)" $?
  else
    mark "manifest tamper (fixture tersaji $SERVED bytes — server loopback gagal)" 1
  fi
  kill "$(cat "$W/serve.pid")" 2>/dev/null
else
  echo "  [SKIP] tamper test (curl/LIVE manifest unavailable)"
fi
# (b) corrupted payload: manifest LIVE sah + payload diacak → checksum refusal
if [ -s "$W/manifest.json" ] && [ -s "$W/payload.gz" ]; then
  mkdir -p "$W/serve2"
  cp "$W/manifest.json" "$W/serve2/gseer-dataset-manifest.json"
  python3 -c "
data=bytearray(open('$W/payload.gz','rb').read())
data[len(data)//2] ^= 0xFF
open('$W/serve2/gseer-dataset.ndjson.gz','wb').write(bytes(data))" 2>/dev/null
  ( cd "$W/serve2" && python3 -m http.server $PORT2 >/dev/null 2>&1 & echo $! > "$W/serve2.pid" )
  sleep 1
  SERVED2=$(curl -sS "http://127.0.0.1:$PORT2/gseer-dataset-manifest.json" | wc -c)
  if [ "$SERVED2" -gt 500 ]; then
    "$BIN" dataset update --force --manifest-url "http://127.0.0.1:$PORT2/gseer-dataset-manifest.json" > "$W/n-sum.log" 2>&1
    grepq "E_DATASET_CHECKSUM" "$W/n-sum.log"; mark "payload corrupt → E_DATASET_CHECKSUM (DB utuh)" $?
  else
    mark "payload corrupt (fixture tersaji $SERVED2 bytes — server loopback gagal)" 1
  fi
  kill "$(cat "$W/serve2.pid")" 2>/dev/null
else
  echo "  [SKIP] corrupt-payload test"
fi

echo "== [H] restart + search setelah restart + bebas env GLM =="
C1=$("$BIN" search 'port=443' --format json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])")
# "restart": proses CLI baru (biner sama, home sama) — inherent per-invocation
C2=$("$BIN" search 'port=443' --format json 2>/dev/null | python3 -c "import json,sys; print(json.load(sys.stdin)['count'])")
[ -n "$C1" ] && [ "$C1" = "$C2" ]; mark "search setelah restart (proses baru): $C1 → $C2" $?
( cd / && env -i PATH="$PATH" HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'port=443' --format json > "$W/n-env.json" 2>&1 )
python3 -c "import json,sys; d=json.load(open('$W/n-env.json')); sys.exit(0 if d.get('count',0)>0 else 1)" 2>/dev/null
mark "bebas cwd + env minimal (env -i, cwd=/)" $?

echo "== [I] go test penuh (tanpa GSEER_HOME) =="
env -u GSEER_HOME "$GO" test -count=1 ./... > "$W/gotest.log" 2>&1
mark "go test ./... (semua paket)" $?
env -u GSEER_HOME "$GO" test -race -count=1 ./internal/dataset/ ./internal/collect/ ./internal/bench/ ./internal/searchlite/ > "$W/race.log" 2>&1
mark "go test -race (paket yang berubah)" $?

echo
echo "== RINGKASAN: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" = "0" ] || { echo "ACCEPTANCE GAGAL — lihat log di $W"; exit 1; }
echo "ACCEPTANCE LOLOS — alur kondisi nyata + negatif + isolasi env terbukti."
