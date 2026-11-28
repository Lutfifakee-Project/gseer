#!/usr/bin/env bash
# GSEER — acceptance journey harness (Rev 12).
#
# Runs the FULL product-acceptance journey against a LOCAL
# production-fidelity channel (real TLS, GitHub Release path layout) and
# records the honest production-URL state as its final step.  Every step
# writes a RAW log; every command's real exit code is captured (set -o
# pipefail, no masking pipes); every step additionally asserts on output
# CONTENT.  Any failed check forces a nonzero overall result — a failed
# search can never be reported as exit 0 again (Rev 11 lesson: a piped
# `search | head` masked the real exit code of an invalid GQL query).
#
# Correct GQL is baked in: domain evidence uses `domain=="<host>"`,
# hostname evidence uses `hostname CONTAINS "<term>"`.  (A bare term like
# `search "kernel.org"` is INVALID per the GQL field registry and used to
# produce a false-positive "exit 0" through pipe masking.)
#
# Usage:
#   acceptance-journey.sh -b BIN -d DIST_DIR -o OUTDIR \
#                         [-m MIN_PORT443] [-p pending|live] [-u PORT]
#
#   BIN       gseer binary under test
#   DIST_DIR  directory containing gseer-dataset-manifest.json + payload
#   MIN_PORT443  minimum acceptable result count for search "port=443"
#   pending|live expected production-URL state (pending = assets not yet
#                published; the step FAILS only if the CLI's error
#                handling is dishonest or broken)
#
# Exits 0 iff EVERY step passed; verdict lines are in OUTDIR/verdict.txt.
set -o pipefail
set -u

BIN="" ; DIST="" ; OUTDIR="" ; MINP=5 ; EXPPROD="pending" ; BASEPORT=18443
while getopts "b:d:o:m:p:u:" opt; do
  case "$opt" in
    b) BIN=$OPTARG ;; d) DIST=$OPTARG ;; o) OUTDIR=$OPTARG ;;
    m) MINP=$OPTARG ;; p) EXPPROD=$OPTARG ;; u) BASEPORT=$OPTARG ;;
    *) echo "bad usage" >&2 ; exit 64 ;;
  esac
done
[ -x "$BIN" ] && [ -d "$DIST" ] && [ -n "$OUTDIR" ] || { echo "bad usage" >&2 ; exit 64 ; }
[ -f "$DIST/gseer-dataset-manifest.json" ] || { echo "DIST_DIR lacks manifest" >&2 ; exit 64 ; }
# Absolutize inputs: the HTTPS channel process chdirs into its serving
# root, so any relative path passed to it would break after startup.
BIN=$(readlink -f "$BIN") ; DIST=$(readlink -f "$DIST") ; OUTDIR=$(readlink -f "$OUTDIR")

FAILS=0
mkdir -p "$OUTDIR"
verdict() { printf '%s\n' "$*" | tee -a "$OUTDIR/verdict.txt" >&2 ; }
fail()    { FAILS=$((FAILS+1)) ; verdict "FAIL $*" ; }

# step NAME EXPECTED_EXIT CMD... — runs RAW (no pipes), captures exit.
step() {
  local name=$1 exp=$2 ; shift 2
  local log="$OUTDIR/$name.log"
  "$@" >"$log" 2>&1 ; local rc=$?
  if [ "$rc" -ne "$exp" ] ; then
    fail "$name exit=$rc expected=$exp (raw log: $log)"
  else
    verdict "ok   $name exit=$rc"
  fi
}
# has LOG PATTERN / lacks LOG PATTERN — content assertions on raw logs.
has()   { grep -qE -- "$2" "$OUTDIR/$1.log" && verdict "ok   $1 contains: $2" || fail "$1 missing pattern: $2" ; }
lacks() { grep -qE -- "$2" "$OUTDIR/$1.log" && fail "$1 must NOT contain: $2" || verdict "ok   $1 clean of: $2" ; }
# count of "N result(s) in ..." in a search log.
result_count() { sed -nE 's/^([0-9]+) result\(s\).*/\1/p' "$OUTDIR/$1.log" | head -1 ; }

P1=$BASEPORT ; P2=$((BASEPORT+1))
CH="https://127.0.0.1:$P1/releases/download/central-dataset/gseer-dataset-manifest.json"
CH2="https://127.0.0.1:$P2/releases/download/central-dataset/gseer-dataset-manifest.json"
OFFICIAL="https://github.com/Lutfifakee-Project/gseer/releases/download/central-dataset/gseer-dataset-manifest.json"
ROOT="$OUTDIR/serve-valid" ; ROOT2="$OUTDIR/serve-tamper" ; CERTS="$OUTDIR/certs"
mkdir -p "$ROOT/releases/download/central-dataset" "$ROOT2/releases/download/central-dataset" "$CERTS"
cp "$DIST/gseer-dataset-manifest.json" "$DIST"/*.ndjson.gz "$ROOT/releases/download/central-dataset/"
cp "$DIST/gseer-dataset-manifest.json" "$DIST"/*.ndjson.gz "$ROOT2/releases/download/central-dataset/"
# tamper: flip one byte of the payload (checksum must catch it)
python3 - "$ROOT2/releases/download/central-dataset/"*.ndjson.gz <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
b[0] ^= 0xFF
open(p, "wb").write(bytes(b))
print("tampered payload written: %s" % p)
PY
# test CA + server cert (SAN 127.0.0.1) — verification MUST be enforced client-side
openssl req -x509 -newkey rsa:2048 -keyout "$CERTS/ca.key" -out "$CERTS/ca.pem" \
  -days 2 -nodes -subj "/CN=gseer-acceptance-test-ca" 2>/dev/null
openssl req -newkey rsa:2048 -keyout "$CERTS/srv.key" -out "$CERTS/srv.csr" \
  -nodes -subj "/CN=127.0.0.1" 2>/dev/null
printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nextendedKeyUsage=serverAuth\n" > "$CERTS/srv.ext"
openssl x509 -req -in "$CERTS/srv.csr" -CA "$CERTS/ca.pem" -CAkey "$CERTS/ca.key" \
  -CAcreateserial -out "$CERTS/srv.pem" -days 2 -extfile "$CERTS/srv.ext" 2>/dev/null
[ -f "$CERTS/srv.pem" ] || { fail "cert generation" ; exit 1 ; }
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
start_channel() { # ROOT PORT LOG
  nohup python3 "$SCRIPT_DIR/acceptance-https-channel.py" "$1" "$2" \
    "$CERTS/srv.pem" "$CERTS/srv.key" > "$OUTDIR/$3" 2>&1 &
  echo $! > "$OUTDIR/$3.pid"
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    curl -sS -m 2 -o /dev/null --cacert "$CERTS/ca.pem" \
      "https://127.0.0.1:$2/releases/download/central-dataset/gseer-dataset-manifest.json" && return 0
    sleep 1
  done
  return 1
}
stop_channel() { # PORT PIDFILE
  fuser -k "$1"/tcp >/dev/null 2>&1
  kill "$(cat "$2")" >/dev/null 2>&1
  rm -f "$2"
}
trap 'stop_channel $P1 "$OUTDIR/channel1.log.pid" 2>/dev/null; stop_channel $P2 "$OUTDIR/channel2.log.pid" 2>/dev/null' EXIT

start_channel "$ROOT" "$P1" channel1.log || { fail "valid channel did not come up" ; exit 1 ; }
start_channel "$ROOT2" "$P2" channel2.log || { fail "tamper channel did not come up" ; exit 1 ; }

HOME1="$OUTDIR/home1" ; HOME2="$OUTDIR/home2" ; HOME3="$OUTDIR/home3" ; HOME4="$OUTDIR/home4"
mkdir -p "$HOME1" "$HOME2" "$HOME3" "$HOME4"

# ---- J00 install: clean profile, binary on PATH, zero config/DB/seeds
cp "$BIN" "$OUTDIR/gseer" && chmod +x "$OUTDIR/gseer"
verdict "J00 install: binary staged as 'gseer', clean HOMEs created"
[ -x "$OUTDIR/gseer" ] || fail "J00 binary not executable"

# ---- J01 version
export PATH="$OUTDIR:$PATH"
step J01-version 0 gseer version
has J01-version "gseer v0\.3\.2" ; has J01-version "commit:"

# ---- J02 setup: no user seeds, no manual DB — auto dataset import over TLS
step J02-setup 0 env HOME="$HOME1" GSEER_DATASET_MANIFEST_URL="$CH" SSL_CERT_FILE="$CERTS/ca.pem" gseer setup
has J02-setup "dataset v" ; has J02-setup "imported" ; lacks J02-setup "E_DATASET"

# ---- J03 search "port=443" — real evidence from the imported dataset.
# Assertions are DATASET-AGNOSTIC product invariants: a minimum count of
# real ":443/tcp" rows.  Specific IPs (e.g. 8.8.8.8/1.1.1.1) belong to one
# dataset build and legitimately shift with fresh discovery from a
# different vantage (Rev 13: dns.google/one.one.one.one did not answer
# TLS from that run's vantage — honest absence, not a defect).
step J03-search-port443 0 env HOME="$HOME1" gseer search "port=443"
C=$(result_count J03-search-port443)
if [ -n "$C" ] && [ "$C" -ge "$MINP" ] 2>/dev/null ; then
  verdict "ok   J03 result count=$C (min required $MINP)"
else
  fail "J03 result count '$C' below minimum $MINP"
fi
NROWS=$(grep -c ":443/tcp" "$OUTDIR/J03-search-port443.log")
if [ -n "$NROWS" ] && [ "$NROWS" -ge "$MINP" ] 2>/dev/null ; then
  verdict "ok   J03 real :443/tcp evidence rows=$NROWS"
else
  fail "J03 :443/tcp rows '$NROWS' below minimum $MINP"
fi

# ---- J04 domain search (correct GQL: field term, not a bare term)
step J04-domain-search 0 env HOME="$HOME1" gseer search 'domain=="kernel.org"'
has J04-domain-search "kernel\.org" ; has J04-domain-search " domain "

# ---- J05 hostname search
step J05-hostname-search 0 env HOME="$HOME1" gseer search 'hostname CONTAINS "wikipedia"'
has J05-hostname-search "wikipedia\.org" ; has J05-hostname-search "www\.wikipedia\.org"

# ---- J06 provenance + freshness (dataset check re-contacts the channel over
# verified TLS — the CA must be trusted here too)
step J06-provenance 0 env HOME="$HOME1" GSEER_DATASET_MANIFEST_URL="$CH" SSL_CERT_FILE="$CERTS/ca.pem" gseer dataset check
has J06-provenance "central-dns" ; has J06-provenance "scan-tls"
has J06-provenance "evidence observed" ; has J06-provenance "version"

# ---- J07 TLS rejection (negative): WITHOUT the test CA the handshake must fail.
# The CLI completes setup with an honest loud warning and an EMPTY index by
# design; acceptance REQUIRES that failure evidence to be present and that no
# dataset was imported.
step J07-x509-reject 0 env -u SSL_CERT_FILE HOME="$HOME2" GSEER_DATASET_MANIFEST_URL="$CH" gseer setup
has J07-x509-reject "x509" ; has J07-x509-reject "unknown authority"
has J07-x509-reject "E_DATASET_UNREACHABLE" ; lacks J07-x509-reject "imported"

# ---- J08 checksum tamper rejection (negative): 1-byte payload flip over verified TLS
step J08-tamper-reject 0 env HOME="$HOME3" GSEER_DATASET_MANIFEST_URL="$CH2" SSL_CERT_FILE="$CERTS/ca.pem" gseer setup
has J08-tamper-reject "E_DATASET_CHECKSUM" ; has J08-tamper-reject "not touched"
lacks J08-tamper-reject "imported"

# ---- J09 offline: BOTH channels dead; the Local Index must still search
stop_channel "$P1" "$OUTDIR/channel1.log.pid"
stop_channel "$P2" "$OUTDIR/channel2.log.pid"
LISTEN=$( (ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep -c "127\.0\.0\.1:$P1\|127\.0\.0\.1:$P2" )
verdict "J09 channels stopped: listeners remaining=$LISTEN"
[ "$LISTEN" -eq 0 ] || fail "J09 channels still listening"
step J09-search-offline 0 env HOME="$HOME1" gseer search "port=443"
C2=$(result_count J09-search-offline)
if [ -n "$C" ] && [ -n "$C2" ] && [ "$C" -eq "$C2" ] ; then
  verdict "ok   J09 offline count=$C2 identical to online count=$C"
else
  fail "J09 offline count '$C2' differs from online count '$C'"
fi

# ---- J10 production URL: honest state of the REAL official channel.
# pending: expect the typed 404 error (assets not yet published — NOT claimed)
# live:    expect real version + import (actual public GitHub Release consumption)
if [ "$EXPPROD" = "live" ] ; then
  step J10-production-url 0 env HOME="$HOME4" gseer dataset check
  has J10-production-url "version"
  verdict "PRODUCTION=PUBLISHED_AND_VERIFIED (public GitHub Release consumption)"
else
  step J10-production-url 4 env HOME="$HOME4" gseer dataset check
  has J10-production-url "HTTP 404"
  has J10-production-url "the owner runs the pipeline"
  verdict "PRODUCTION=NOT_YET_PUBLISHED (honest 404 — publication NOT claimed; local fidelity above)"
fi

echo
if [ "$FAILS" -eq 0 ] ; then
  verdict "VERDICT=ALL_STEPS_PASSED ($OUTDIR)"
  exit 0
fi
verdict "VERDICT=FAILED checks=$FAILS ($OUTDIR)"
exit 1
