# GSEER — Authorized Active Observation (`gseer scope` / `gseer scan`)

> v0.3.2 (the P2/PAC regime).  This document is the operating manual for
> GSEER's active HTTP/TLS observation.  Read it before your first scan:
> running a scan asserts that you own — or are otherwise authorized to
> observe — the target.  GSEER never infers ownership and never probes
> a target without an explicit, live scope.

## The authorization model

Active observation is **default-deny**.  Every connection — the first
request AND every redirect hop AND every reconnect — passes the gateway
(`internal/observe`), which checks the scope registry in your database:

| Situation | Result |
| --- | --- |
| No scope matches the target | **DENY** (`NO_SCOPE`) |
| Matching scope revoked | **DENY** (`SCOPE_REVOKED`) |
| Matching scope expired | **DENY** (`SCOPE_EXPIRED`) |
| Matching scope is a deny row | **DENY** (`SCOPE_MODE_DENY`) |
| Protocol not in the scope's list | **DENY** (`PROTOCOL_NOT_PERMITTED`) |
| Port not in the scope's list | **DENY** (`PORT_NOT_PERMITTED`) |
| Private/loopback address without an address-level scope | **DENY** (`PRIVATE_UNSCOPED`) |
| Target does not resolve | **DENY** (`DNS_NO_ANSWER` — fail-closed) |
| Per-run request budget exhausted | the hop is **recorded, not sent** |
| Accumulated response-byte budget exhausted | the hop is **recorded, not sent** (the run reports `truncated`, never a complete response) |
| Authorization audit could not be persisted | **DENY** (`AUDIT_UNAVAILABLE` — FAIL CLOSED: no probe may run unaudited) |
| Scope already at its simultaneous-observations limit | **REFUSED** (`E_SCOPE_BUSY`, exit 1 — no probe sent; not a denial, a concurrency answer) |

Every decision — allow AND deny — is appended to `scan_audits`
(`gseer scope audit`).  A deny **never** generates network traffic.

## Managing scopes

```console
# A loopback dev server (the supported way to observe a service you run):
gseer scope add cidr 127.0.0.1/32 --protocols http,tls --ports 8080,8443 \
    --note "my dev server" --expires-at 2026-12-31T23:59:59Z

# A domain you own (covers the name and its subdomains for suffix scopes):
gseer scope add domain myserver.example --protocols http --ports 80

gseer scope list          # history included: revoked/expired rows stay visible
gseer scope audit         # the gateway decision trail
gseer scope revoke 3      # effective on the NEXT connection
```

A scope permits ONLY what it lists: an empty protocol or port list
would authorize nothing and is refused at creation (default-deny is
expressed by NOT having a scope, never by an empty one).

**Private networks**: loopback, RFC 1918, ULA, link-local and CGNAT
addresses are reachable ONLY when a scope explicitly covers the address
or range (`--kind cidr --value 127.0.0.1/32`, `--kind ip --value
10.0.0.5`).  A hostname-scoped target that resolves into a private
range is refused — name the range explicitly.

**Authorization basis is yours to declare**: the `--note` field exists
for exactly that (ownership, ticket, written permission).  Do not scan
targets you are not authorized to observe.

## The two observers

They are separate by contract — separate commands, separate scope
protocol, separate provenance labels:

| Observer | Command | Scope protocol | Provenance | Records |
| --- | --- | --- | --- | --- |
| HTTP | `gseer scan http --target H --port P` | `http` | `scan-http` | status, title, server, content-type, redirect chain |
| TLS | `gseer scan tls --target H --port P` | `tls` | `scan-tls` | TLS version, cipher, certificate (subject/issuer CN, expiry, SANs, serial) |

```console
gseer scan http --target localhost --port 8080
gseer scan tls  --target localhost --port 8443
```

Behavior details that matter:

- **DNS rebinding protection**: the gateway resolves the hostname once,
  validates every returned address against the registry, and the
  observer dials ONLY the validated address (the Host header still
  carries your hostname for virtual hosting).  The hostname is never
  re-resolved behind the gateway's back.
- **Redirect revalidation**: each hop re-enters the gateway.  A
  redirect to `https://` is RECORDED, not followed — run
  `gseer scan tls` for it (the observers never cross scopes).
- **Race handling (three independent gates, domain-aware)**: (1) the
  initial authorization plans the run; (2) the FIRST hop re-authorizes
  immediately before its request is built — a scope revoked between the
  two denies with **nothing sent** (`E_SCOPE_DENIED`, exit 5); every
  redirect hop re-authorizes its NEW destination the same way; and (3)
  every dial — first, retry, reconnect — passes `Gateway.Revalidate`
  (the ORIGINAL hostname AND the pinned address against the CURRENT
  registry, audited) immediately before the socket connect.
  Re-validation is **domain-aware**: `domain` and `domain_suffix`
  scopes keep matching by NAME (the exact suffix/label-boundary rules
  of authorization), `ip`/`cidr` scopes and the private-address policy
  keep matching by the pinned address, and protocol/port/expiry/
  revocation are all re-checked.  No DNS resolution happens inside
  re-validation — the hostname is never re-resolved behind the gateway,
  so rebinding protection is preserved.  A bare IP-literal target is
  NOT covered by a domain scope (host matching is name-based).  The
  residual window between that final registry read and the connect
  syscall is irreducible in userspace and is documented here rather
  than overstated: the guarantee is "no connection without a
  just-audited allow of the original hostname AND the pinned address",
  never "atomic".
- **Audit persistence fails closed (FIX A)**: every allow is durably
  persisted to `scan_audits` BEFORE the decision is returned; if the
  insert fails, the allow becomes an explicit `AUDIT_UNAVAILABLE` deny
  and nothing connects.  A failed insert writes no row, so no duplicate
  audit rows can appear; denies surface the audit failure in their
  error while keeping the original denial.
- **Concurrent observations are lease-enforced (FIX D + lease
  integrity)**: `max-concurrency` is a SCOPE-level limit across ALL
  processes — per scope, NOT a global engine-wide quota (two scopes
  that cover overlapping targets have independent budgets).  A run
  holds one of the scope's `scan_leases` slots (1..N) for its whole
  duration in the shared database — SQLite and PostgreSQL alike.  Each
  acquisition owns a per-acquisition cryptographic TOKEN (128-bit
  crypto/rand): release and renewal are TOKEN-scoped, so a
  late-finishing old observation can never delete or renew a newer
  holder's lease on the same slot.  While the run is live a renewal
  heartbeat extends the lease every TTL/3 (~40 s for the 2-minute TTL)
  — token-verified, never resurrecting a stolen or lapsed lease.  On a
  renewal failure (lease stolen/expired OR lease-storage error) the
  observation FAILS CLOSED: no NEW connection is opened (in-flight
  work completes and is recorded honestly).  A further scan while all
  slots are live is refused with `E_SCOPE_BUSY` (exit 1, nothing
  probed — a concurrency answer, not an authorization denial).  A
  crashed holder's lease expires after the TTL (2 minutes) and is then
  stealable, so stale locks cannot accumulate; double release is a
  no-op; heartbeat goroutines never outlive their run.
- **Bounded by the scope**: per-run request budget (`max_requests` —
  redirect hops count) and the accumulated response-byte budget
  (`max_total_bytes`, engine default 64 KiB for HTTP) both come from
  the acting scope.  The byte budget is ACCUMULATED for the entire run:
  the metric is bytes actually read from HTTP response bodies (headers
  excluded), counted across EVERY redirect hop, never reset on a
  redirect; the single one-byte truncation probe is counted because it
  is read.  A mid-body read error is recorded as a failure — never as a
  complete response.
- **Capture, not verification**: the TLS observer records the
  certificate the server presented — self-signed and name-mismatched
  certificates are data, not errors.  Trust evaluation is your job.
- **Failure is not absence**: a refused connection or failed handshake
  is recorded as an observation of failure (evidence
  `scan.result="failed"`), never as evidence that an asset does not
  exist.

## Where the data lands

Observations flow through the SAME ingestion path as passive
collection (suppression gate, L1/L2 idempotency, provenance, evidence
JSONB).  HTTP evidence keys (`http.status/title/server`) and TLS keys
(`tls.version/cert_subject_cn/cert_issuer_cn/cert_expiry`) feed the
existing `latest_http` / `latest_tls` views, so scans are searchable
immediately:

```console
gseer search 'http.status == 200'
gseer search 'tls.cert_expiry > "2027-01-01"'
gseer search 'sources CONTAINS "scan-http"'
gseer host 127.0.0.1            # self-hosted profile
```

Search stays read-only and never scans (ADR-0010, unchanged).

## Databases

- **PostgreSQL (self-hosted)**: migration `0018_active_observation`
  extends the deferred `scopes` table in place and creates the
  append-only `scan_audits`.  The additive `gseer_app` grants (SELECT/
  INSERT/UPDATE on scopes; SELECT/INSERT on scan_audits) ship in the
  migration; the fail-closed effective-privilege audit still passes
  (sequence grants are deliberately absent — identity columns need
  none, and the audit treats any sequence privilege as a violation).
- **SQLite (personal)**: migration `0002_active_observation` gives
  personal mode the full scope registry and audit log (1:1 semantics;
  CSV protocol/port lists, fixed-width UTC timestamps).

Deployment order is unchanged (docs/DEPLOYMENT.md §3.1): bootstrap →
migrate → grants → audit.

## Honesty rules (unchanged, now extended)

1. Fixtures are never real data; `scan-http` / `scan-tls` provenance is
   never a fixture label and fixtures are never scan results.
2. Nothing observes uninvoked: no scheduler, no daemon — `gseer scan`
   is an explicit command, exactly like `gseer collect`.
3. A successful build, a passing mocked test, or a CLI command existing
   is not proof of real observation — verification drives a real local
   server and checks the stored evidence.
4. Never claim an asset is absent because a probe failed.
