#!/usr/bin/env bash
# scripts/v032-final-acceptance.sh — REGRESSION ACCEPTANCE DRIVER (GSEER v0.3.2).
#
# Alur: UNZIP -> TEST -> GO TEST -> TEST BINARY -> SEARCH korpus -> TEST LAINNYA.
#
# PEMISAHAN BUKTI (koreksi owner):
#   - Bagian [D] memakai KORPUS EVALUASI SINTETIS (--load-fixtures).  Korpus
#     fixture adalah data sintetis berlabel: ia MENGUJI mesin search, GQL,
#     provenance, dan freshness, tetapi TIDAK dihitung sebagai bukti discovery
#     internet nyata.
#   - Bukti "BANYAK DOMAIN/IP NYATA dari sumber terdokumentasi" ada di driver
#     terpisah: scripts/v032-clean-user-acceptance.sh  (INSTALL -> VERIFY VERSION
#     -> SETUP retrieval+verifikasi shared-index -> SEARCH ratusan IP/domain
#     nyata dengan evidence -> NO-DISCOVERY).  Itulah acceptance perjalanan
#     clean user (target produk).
#
# Semua berjalan di home terisolasi (tidak menyentuh data operator sungguhan).
# Search hanya membaca index; satu-satunya data live adalah collect DNS pasif
# EKSPLISIT atas example.com (sumber pasif yang diizinkan).  Gate observasi
# aktif terbukti fail-closed: `gseer scan` tanpa scope DITOLAK.
#
# Env opsional:
#   GSEER_TEST_PG_ADMIN  superuser DSN — bila diset, test integrasi PostgreSQL
#                        (migrations IT/UT) ikut dijalankan.
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

W=$(mktemp -d /tmp/gseer-final-acc.XXXX)
H="$W/home"; mkdir -p "$H"
export GSEER_HOME="$H/.gseer"
BIN="$W/gseer"
COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# catatan: GOPATH/GOCACHE WAJIB di luar repo — test governance memindai semua
# .go di bawah direktori repo dan akan memindai module cache bila di dalam.
export GOPATH="${GSEER_GOPATH:-$W/gopath}" GOCACHE="${GSEER_GOCACHE:-$W/gocache}"

echo "== GSEER v0.3.2 REGRESSION ACCEPTANCE $(date -u +%FT%TZ) =="
echo " repo: $REPO_ROOT"
echo " baseline commit: $COMMIT"

echo "== [A] TEST: build all packages + vet =="
"$GO" build ./... >/dev/null 2>&1; mark "go build ./... (semua paket)" $?
"$GO" vet ./... >/dev/null 2>&1; mark "go vet ./... (clean)" $?

echo "== [B] GO TEST: unit suite penuh =="
# GSEER_HOME di-unset: test first-run mengelola HOME/GSEER_HOME sendiri;
# bocornya env ini membuat test menulis config ke home driver (bukan temp test).
env -u GSEER_HOME "$GO" test -count=1 ./... > "$W/gotest.log" 2>&1
mark "go test -count=1 ./... (25 paket)" $?
if [ -n "${GSEER_TEST_PG_ADMIN:-}" ]; then
  GSEER_TEST_REQUIRE=1 env -u GSEER_HOME "$GO" test -tags integration -count=1 \
    -run 'TestMigrationStatusBranches|TestV010ToV020UpgradePath' \
    ./internal/storage/postgres/ > "$W/it.log" 2>&1
  mark "PostgreSQL integration IT/UT (GSEER_TEST_PG_ADMIN)" $?
else
  echo "  [SKIP] PostgreSQL integration (set GSEER_TEST_PG_ADMIN utk menjalankan)"
fi

echo "== [C] TEST BINARY: build rilis + version terverifikasi =="
"$GO" build -trimpath -ldflags "-X github.com/Lutfifakee-Project/gseer/internal/version.Version=v0.3.2 -X github.com/Lutfifakee-Project/gseer/internal/version.Commit=$COMMIT -X github.com/Lutfifakee-Project/gseer/internal/version.BuiltAt=$TS" -o "$BIN" ./cmd/gseer >/dev/null 2>&1
mark "build binary rilis (trimpath + ldflags)" $?
VER_OUT=$("$BIN" version 2>&1)
echo "$VER_OUT" | grep -q "v0.3.2" && mark "gseer version = v0.3.2" 0 || mark "gseer version = v0.3.2" 1
if [ "$COMMIT" = "unknown" ]; then
  echo "  [SKIP] version commit == baseline (repo diekstrak tanpa .git — set GSEER_COMMIT utk memverifikasi)"
  [ -n "${GSEER_COMMIT:-}" ] && { echo "$VER_OUT" | grep -q "$GSEER_COMMIT" && mark "version commit == GSEER_COMMIT" 0 || mark "version commit == GSEER_COMMIT" 1; }
else
  echo "$VER_OUT" | grep -q "$COMMIT" && mark "version commit == baseline commit" 0 || mark "version commit == baseline commit" 1
fi
# semantik v031 J1/J2: first-run init dulu, lalu doctor dinilai dari pola output
HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" >/dev/null 2>&1; mark "first-run init personal mode (sebelum doctor)" $?
DOC=$(HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" doctor 2>&1); echo "$DOC" | grep -qE "(PASS|ok \[)"; mark "doctor menilai kesehatan (output berisi PASS/ok)" $?

echo "== [D] SEARCH: korpus evaluasi SINTETIS (fixture — BUKAN bukti discovery internet) =="
echo y | HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" setup --load-fixtures >/dev/null 2>&1; mark "setup --load-fixtures (korpus evaluasi)" $?
HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" doctor >/dev/null 2>&1; mark "doctor setelah setup" $?
J5=$(HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'port==443 && title CONTAINS "login"' 2>&1); echo "$J5" | grep -q "result"; mark "search GQL korpus (port+title)" $?
J6=$(HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" source add acc-dns --type dns --seeds example.com --enable --yes 2>&1); echo "$J6" | grep -q "Registered source"; mark "registrasi sumber DNS pasif" $?
J7=$(HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" collect run --source acc-dns 2>&1); echo "$J7" | grep -q '"done": true'; mark "collect eksplisit (DNS example.com, live — permitted passive)" $?
NIP=$(HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'asset_kind=="ip"' -o json 2>/dev/null | python3 -c 'import json,sys; o=json.load(sys.stdin); r=o["rows"] if isinstance(o,dict) else o; print(len(r))' 2>/dev/null || echo 0)
[ "${NIP:-0}" -ge 1 ] 2>/dev/null; mark "search IP (halaman pertama, rows=$NIP >= 1)" $?
NDOM=$(HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'asset_kind=="domain"' -o json 2>/dev/null | python3 -c 'import json,sys; o=json.load(sys.stdin); r=o["rows"] if isinstance(o,dict) else o; print(len(r))' 2>/dev/null || echo 0)
[ "${NDOM:-0}" -ge 1 ] 2>/dev/null; mark "search domain (halaman pertama, rows=$NDOM >= 1)" $?
HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'asset_kind=="domain"' -o table > "$W/search-table.txt" 2>&1
echo "----- snapshot tabel search (domain) -----"; sed -n '1,20p' "$W/search-table.txt"; echo "----- akhir snapshot -----"
HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'asset_kind=="ip"' -o json 2>/dev/null | python3 -c '
import json,sys
o=json.load(sys.stdin)
rows=o["rows"] if isinstance(o,dict) else o
need=["sources","first_seen","last_seen"]
ok=all(all(k in r for k in need) for r in rows) if rows else False
sys.exit(0 if ok else 1)' 2>/dev/null
mark "evidence/provenance + freshness (sources/first_seen/last_seen) ada di hasil" $?
HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'asset_value=="example.com"' 2>&1 | grep -q "result"; mark "seed domain example.com tercari" $?
HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'asset_kind=="ip"' -o json > "$W/exp.json" 2>/dev/null && HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" export --format csv --out "$W/exp.csv" 'asset_kind=="ip"' >/dev/null 2>&1
[ -s "$W/exp.csv" ]; mark "export CSV hasil search" $?

echo "== [E] TEST LAINNYA: gate no-scan + garansi search-pasif =="
HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" scan http --target example.com --port 443 >/dev/null 2>&1
[ $? -ne 0 ]; mark "scan TANPA scope ditolak fail-closed (target tak otorisasi)" $?
BEFORE=$(HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'asset_kind=="domain"' -o json 2>/dev/null | python3 -c 'import json,sys; o=json.load(sys.stdin); r=o["rows"] if isinstance(o,dict) else o; print(len(r))' 2>/dev/null || echo 0)
HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'domain CONTAINS "nonexistent-domain-xyz"' >/dev/null 2>&1
AFTER=$(HOME="$H" GSEER_HOME="$GSEER_HOME" "$BIN" search 'asset_kind=="domain"' -o json 2>/dev/null | python3 -c 'import json,sys; o=json.load(sys.stdin); r=o["rows"] if isinstance(o,dict) else o; print(len(r))' 2>/dev/null || echo 0)
[ "$BEFORE" = "$AFTER" ]; mark "search TIDAK menambah aset (index-only; $BEFORE->$AFTER)" $?

echo "== HASIL =="
echo " PASSED: $PASS  FAILED: $FAIL"
cp -f "$W/gotest.log" "${FINAL_ACC_LOGDIR:-/tmp}/final-acc-gotest.log" 2>/dev/null
[ -n "${GSEER_TEST_PG_ADMIN:-}" ] && cp -f "$W/it.log" "${FINAL_ACC_LOGDIR:-/tmp}/final-acc-it.log" 2>/dev/null
[ "$FAIL" = "0" ] && echo " REGRESSION ACCEPTANCE: PASS" || echo " REGRESSION ACCEPTANCE: FAIL"
chmod -R u+w "$W" 2>/dev/null; rm -rf "$W" 2>/dev/null
[ "$FAIL" = "0" ]
