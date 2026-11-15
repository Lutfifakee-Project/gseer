#!/usr/bin/env bash
# scripts/v032-acceptance.sh — GSEER v0.3.2 acceptance battery.
#
# Drives the REAL compiled gseer binary through the active-observation
# journey in an ISOLATED temporary home (never the operator's real GSEER
# data), against operator-owned LOOPBACK targets this script starts
# itself (a plain HTTP server and a TLS server).  Nothing here touches
# an external network.
#
# Contract (same as v031-acceptance.sh):
#   - every check prints an explicit [PASS]/[FAIL] line;
#   - a failed REQUIRED check aborts the battery immediately (fail-fast)
#     with a non-zero exit;
#   - the final summary counts ONLY independently executed assertions;
#   - the claimed pass count is whatever actually ran — never hardcoded.
#
# Environment:
#   GSEER_BIN  path to a prebuilt gseer binary; when unset the script
#              builds one from this repository (requires go on PATH).
#   KEEP_HOME=1  do not delete the temporary home on exit (debugging).
set -u

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)

# --- isolated environment ---------------------------------------------------
H=$(mktemp -d /tmp/gseer-v032-accept.XXXXXX) || exit 2
trap 'rc=$?; [ "${KEEP_HOME:-0}" = "1" ] || rm -rf "$H"; exit $rc' EXIT
export HOME="$H"
mkdir -p "$H"

HTTP_PORT=18191
TLS_PORT=18192

# --- operator-owned loopback targets ---------------------------------------
cat > "$H/http_target.py" <<'PYEOF'
import http.server, socketserver
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "gseer-v032-accept/1.0")
        self.send_header("Content-Type", "text/html")
        body = b"<html><head><title>GSEER v032 Acceptance</title></head><body>ok</body></html>"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("127.0.0.1", int(__import__("sys").argv[1])), H) as s:
    s.serve_forever()
PYEOF

cat > "$H/tls_target.py" <<'PYEOF'
import http.server, ssl, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b"tls ok")
    def log_message(self, *a): pass
httpd = socketserver.TCPServer(("127.0.0.1", int(sys.argv[1])), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PYEOF

# A self-signed certificate generated locally (the operator's own cert).
openssl_req_bin=$(command -v openssl || true)
if [ -n "$openssl_req_bin" ]; then
    "$openssl_req_bin" req -x509 -newkey rsa:2048 -nodes -keyout "$H/tls.key" \
        -out "$H/tls.crt" -days 2 -subj "/CN=gseer-v032-accept.local" >/dev/null 2>&1
fi
if [ ! -s "$H/tls.crt" ]; then
    echo "[FAIL] T0 self-signed certificate could not be generated (openssl missing)"
    exit 1
fi

# --- binary ----------------------------------------------------------------
GSEER_BIN="${GSEER_BIN:-}"
if [ -z "$GSEER_BIN" ]; then
    (cd "$REPO_ROOT" && go build -o "$H/gseer" ./cmd/gseer) || exit 3
    GSEER_BIN="$H/gseer"
fi

# --- checks ----------------------------------------------------------------
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  [PASS] $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  [FAIL] $*"; }
need() { if [ "$FAIL" -gt 0 ]; then echo "ABORT: a REQUIRED check failed"; exit 1; fi; }
g()    { "$GSEER_BIN" "$@"; }

echo "[A] Isolated fresh install + schema head (personal migration 0002)"
out=$(g 2>&1); rc=$?
echo "$out" | grep -q "PERSONAL MODE" && ok "A1 first run auto-inits personal mode" || { bad "A1 first run: $out"; exit 1; }
out=$(g doctor 2>&1)
echo "$out" | grep -qiE "personal|ok" && ok "A2 doctor runs on the v0.3.2 schema" || bad "A2 doctor: $out"

echo "[B] Default-deny: NO scope ⇒ NO probe (exit 5, no scan-audit allow)"
out=$(g scan http --target 127.0.0.1 --port "$HTTP_PORT" 2>&1); rc=$?
[ "$rc" = "5" ] && ok "B1 unscoped scan exits 5 (auth)" || bad "B1 exit=$rc: $out"
echo "$out" | grep -q "E_SCOPE_DENIED" && ok "B2 typed E_SCOPE_DENIED" || bad "B2: $out"

echo "[C] Targets (operator-owned loopback servers)"
python3 "$H/http_target.py" "$HTTP_PORT" >/dev/null 2>&1 &
HTTP_PID=$!
python3 "$H/tls_target.py" "$TLS_PORT" "$H/tls.crt" "$H/tls.key" >/dev/null 2>&1 &
TLS_PID=$!
sleep 1
cleanup_servers() { kill "$HTTP_PID" "$TLS_PID" 2>/dev/null || true; }
trap 'rc=$?; cleanup_servers; [ "${KEEP_HOME:-0}" = "1" ] || rm -rf "$H"; exit $rc' EXIT

echo "[D] Scope registry"
out=$(g scope add cidr 127.0.0.1/32 --protocols http,tls --ports "$HTTP_PORT,$TLS_PORT" --note "operator-owned loopback acceptance targets" 2>&1); rc=$?
[ "$rc" = "0" ] && echo "$out" | grep -q "Registered scope" && ok "D1 scope add" || { bad "D1: $out"; exit 1; }
out=$(g scope list 2>&1)
echo "$out" | grep -q "allow-active" && ok "D2 scope list shows active" || bad "D2: $out"
out=$(g scope add cidr 127.0.0.1/32 --protocols http --ports 9 2>&1); rc=$?
[ "$rc" != "0" ] && echo "$out" | grep -q "E_SCOPE_EXISTS" && ok "D3 duplicate scope refused (typed)" || bad "D3: $out"

echo "[E] HTTP observation (authorized; scope protocol http)"
out=$(g scan http --target 127.0.0.1 --port "$HTTP_PORT" 2>&1); rc=$?
[ "$rc" = "0" ] && echo "$out" | grep -q "status=200" && ok "E1 scan http status=200" || { bad "E1 exit=$rc: $out"; exit 1; }
echo "$out" | grep -q "GSEER v032 Acceptance" && ok "E2 title captured" || bad "E2: $out"
echo "$out" | grep -q "scan-http" && ok "E3 provenance scan-http" || bad "E3: $out"

echo "[F] TLS observation (authorized; scope protocol tls)"
out=$(g scan tls --target 127.0.0.1 --port "$TLS_PORT" 2>&1); rc=$?
[ "$rc" = "0" ] && echo "$out" | grep -q "TLS" && ok "F1 scan tls handshake" || { bad "F1 exit=$rc: $out"; exit 1; }
echo "$out" | grep -q "gseer-v032-accept.local" && ok "F2 certificate subject CN captured" || bad "F2: $out"
echo "$out" | grep -q "scan-tls" && ok "F3 provenance scan-tls" || bad "F3: $out"

echo "[G] GQL search over REAL scan observations (read-only)"
out=$(g search 'http.status == 200' 2>&1); rc=$?
[ "$rc" = "0" ] && echo "$out" | grep -q "result" && ok "G1 GQL http.status==200 finds the scan" || bad "G1: $out"
out=$(g search "tls.cert_subject_cn == \"gseer-v032-accept.local\"" 2>&1); rc=$?
[ "$rc" = "0" ] && echo "$out" | grep -q "result" && ok "G2 GQL cert_subject_cn finds the TLS scan" || bad "G2: $out"
out=$(g search 'sources CONTAINS "scan-http"' 2>&1)
echo "$out" | grep -q "127.0.0.1" && ok "G3 sources facet carries scan-http" || bad "G3: $out"

echo "[H] Audit trail (allow AND deny)"
out=$(g scope audit 2>&1)
echo "$out" | grep -q "allow" && ok "H1 allow decisions audited" || bad "H1: $out"
echo "$out" | grep -q "deny" && ok "H2 the pre-scope denial is in the trail" || bad "H2: $out"

echo "[I] Revocation takes effect (next connection denied, audited)"
out=$(g scope revoke 1 2>&1); rc=$?
[ "$rc" = "0" ] && echo "$out" | grep -q "Revoked" && ok "I1 scope revoke" || { bad "I1: $out"; exit 1; }
out=$(g scan http --target 127.0.0.1 --port "$HTTP_PORT" 2>&1); rc=$?
[ "$rc" = "5" ] && echo "$out" | grep -q "E_SCOPE_DENIED" && ok "I2 revoked scan denied (exit 5)" || bad "I2 exit=$rc: $out"
out=$(g scope audit 2>&1)
echo "$out" | grep -q "SCOPE_REVOKED" && ok "I3 revocation denial audited" || bad "I3: $out"

echo "[J] Honesty: failed observation recorded, never absence"
# NOTE: scope id 1 was revoked in section I and (kind, value) uniqueness
# includes revoked rows (history is preserved by design), so this check
# uses a DIFFERENT scope value that still covers the loopback address.
out=$(g scope add cidr 127.0.0.0/8 --protocols http --ports 18199 --note "nothing listens here" 2>&1); rc=$?
[ "$rc" = "0" ] && ok "J1 scope for an unlistening port" || bad "J1: $out"
out=$(g scan http --target 127.0.0.1 --port 18199 2>&1); rc=$?
[ "$rc" = "0" ] && echo "$out" | grep -q "FAILED" && ok "J2 failed probe recorded honestly (exit 0)" || bad "J2 exit=$rc: $out"

echo "[K] Backup/restore on the v0.3.2 schema"
out=$(g db backup --out "$H/b.bin" 2>&1); rc=$?
[ "$rc" = "0" ] && ok "K1 backup on the new schema" || bad "K1: $out"
out=$(g db restore --yes "$H/b.bin" 2>&1); rc=$?
[ "$rc" = "0" ] && ok "K2 restore on the new schema" || bad "K2: $out"
out=$(g search 'http.status == 200' 2>&1); rc=$?
[ "$rc" = "0" ] && echo "$out" | grep -q "result" && ok "K3 observations survive restore" || bad "K3: $out"

cleanup_servers

echo
echo "ACCEPTANCE RESULT: $PASS / $((PASS+FAIL)) passed, $FAIL failed"
[ "$FAIL" = "0" ]
