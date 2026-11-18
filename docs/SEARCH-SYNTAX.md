# GSEER Search Syntax — Official GQL Reference

GSEER's query language is **GQL** (the GSEER Query Language), specified in
SPEC-04 §3. This document is the official, grammar-true syntax reference:
every example below is verified against the grammar implementation and —
where marked **[v1]** — against the real central dataset v1 release
artifact (269 observations, 202 asset rows) through the CLI journey
`setup` → `dataset update` → `search`. The compatibility layer (the
second half of this document) stays additive: every query that was valid
before it stays valid, byte for byte.

## 1. Grammar

GQL is a boolean expression over typed comparisons:

```
query      := or
or         := and ( "||" | "or"  and )*        — lowest precedence
and        := not ( "&&" | "and" not )*
not        := ( "!" | "not" ) not | primary
primary    := "(" or ")" | comparison | exists | free-text
comparison := field op value
op         := "=" | "==" | "!=" | "<" | "<=" | ">" | ">="
            | "IN" | "CONTAINS" | "IN_CIDR" | "IN_DOMAIN" | "*="
exists     := "exists" "(" field ")" | bare-known-field
value      := double-quoted string (escapes: \\ \" \n …) | bare integer
```

Precedence is `!` > `&&` > `||`; parentheses group. `=` is sugar for
`==`; `AND`/`OR`/`NOT` work in any casing. Parse failures abort with
`GQL_E_PARSE` / `GQL_E_LEX` at the exact position plus a did-you-mean
hint; semantic failures abort with `GQL_E_FIELD` (unknown field),
`GQL_E_OP` (operator not valid for the field) or `GQL_E_TYPE` (value
type). Bounds: ≤ 1024 AST nodes, depth ≤ 32, IN lists ≤ 256 elements.
Search runs **locally only** — it never triggers discovery, collection,
probing or scanning (ADR-0010).

## 2. Value rules

| Rule | Example |
| --- | --- |
| String values are ALWAYS double-quoted | `protocol="https"` |
| Integer values are bare (or quoted-numeric, coerced) | `port=443`, `port="443"` |
| A quoted integer coerces in place (compat) | `port="443"` ≡ `port=443` |
| A quoted non-numeric value on an int field is a type error with a hint | `port="https"` → `GQL_E_TYPE` |
| Timestamps are quoted RFC 3339 (or dates for the date fields) | `observed_at > "2026-11-18T00:00:00Z"` |
| Booleans are the quoted literals `"true"` / `"false"` | `stale=="false"` |
| Dotted values (IPs, hostnames) must be quoted | `ip="1.1.1.1"` |
| A bare word that is not a known field is free text | `nginx` |

## 3. Field registry (search_index surface)

| Field | Aliases | Type | Operators |
| --- | --- | --- | --- |
| `ip` | — | string(inet) | `==` `!=` `IN` `IN_CIDR` `*=` |
| `asset_value` | — | string | `==` `!=` `IN` `CONTAINS` `*=` |
| `asset_kind` | — | string | `==` `!=` `IN` |
| `domain` | — | string | `==` `!=` `IN` `CONTAINS` `*=` `IN_DOMAIN` |
| `hostname` | — | string | `==` `!=` `IN` `CONTAINS` `*=` `IN_DOMAIN` |
| `host_or_ip` | `host` | string | lowered to hostname **or** ip |
| `port` | — | int | `==` `!=` `<` `<=` `>` `>=` `IN` |
| `transport` | `base_protocol` | string | `==` `!=` `IN` |
| `protocol` | — | string | `==` `!=` `IN` |
| `asn` | — | int | `==` `!=` `<` `<=` `>` `>=` `IN` |
| `asn_org` | `org`, `organization` | string | `==` `!=` `IN` `CONTAINS` `*=` |
| `geo_country` | `country`, `ip_country` | string | `==` `!=` `IN` |
| `geo_region` | `region`, `ip_region` | string | `==` `!=` `IN` |
| `geo_city` | `city`, `ip_city` | string | `==` `!=` `IN` `CONTAINS` `*=` |
| `http.status` | `status`, `status_code` | int | ordered + `IN` |
| `http.title` | `title` | string | `==` `!=` `IN` `CONTAINS` `*=` |
| `http.server` | `server` | string | `==` `!=` `IN` `CONTAINS` `*=` |
| `tls.version` | `tls_version` | string | `==` `!=` `IN` |
| `tls.cert_subject_cn` | `cert_subject`, `cert.subject`, `cert_subject_cn`, `cert.subject.cn` | string | `==` `!=` `IN` `CONTAINS` `*=` |
| `tls.cert_issuer_cn` | `cert_issuer`, `cert.issuer`, `cert_issuer_cn`, `cert.issuer.cn` | string | `==` `!=` `IN` `CONTAINS` `*=` |
| `tls.cert_expiry` | `cert_expiry` | timestamp | ordered |
| `tls.cert_serial` | `cert_sn`, `cert.sn` | string | `==` `!=` `IN` `CONTAINS` `*=` |
| `tls.cert_sans_dns` | `cert.domain`, `cert_domain` | string | `CONTAINS` covers exact SANs and subdomains |
| `technologies` | `tech`, `fingerprint` | list | `CONTAINS` |
| `sources` | — | list | `CONTAINS` |
| `first_seen`, `last_seen` | — | timestamp | ordered |
| `observed_at` | — | timestamp | ordered (v0.3.2) |
| `stale` | — | bool | `==` `!=` |
| `is_domain`, `is_ipv6`, `cert.is_expired` | — | bool (derived) | `==` `!=` |
| `after`, `before` | `ip_after`, `ip_before` | date → last_seen | ordered |
| `cert.not_after.after`, `cert.not_after.before` | — | date → tls.cert_expiry | ordered |

## 4. Freshness semantics (honest, v0.3.2)

Three DISTINCT time surfaces — choose the one that answers your question:

| Surface | Meaning | Moves when |
| --- | --- | --- |
| `observed_at` | the row's REAL evidence time — the newest observation's `observed_at` (migration 0022 PG / 0006 SQLite) | only when NEW EVIDENCE arrives |
| `last_seen` | the store's ingest stamp for the row (also what `after`/`before` lower to) | every ingest **or** dataset import |
| `first_seen` | the first ingest stamp | never |

`observed_at > "2026-11-18T00:00:00Z"` answers "how old is the EVIDENCE?";
`after="2026-01-01"` answers "imported/ingested since when?". The
`gseer dataset status` freshness line reports the artifact's own
`oldest/newest_observed_at` window — the same clock `observed_at`
searches.

## 5. Verified examples [v1]

Run against the real central dataset v1 (exact result counts, pinned by
`TestCentralDatasetV1RealEvidenceE2E`):

```
port=443                                   → 15   port="443"             → 15
protocol="https"                           → 15   port=443 && protocol="https" → 15
ip="1.1.1.1"                               → 1    domain="example.com"   → 1
host="www.example.com"                     → 1    asn="13335"            → 20
country="US"                               → 47   is_ipv6="true"         → 24
port=443 && country!="US"                  → 3    sources CONTAINS "central-ctlog" → 64
tls_version="TLS 1.3"                      → 15   cert.issuer CONTAINS "Cloudflare" → 4
cert.subject="example.com"                 → 1    cert.domain CONTAINS "example."   → 4
organization CONTAINS "Fastly"             → 8    "cloudflare" (free text) → 28
stale=="false"                             → 202  observed_at > "2026-11-18T00:00:00Z" → 202
title=="Dashboard"                         → 0    server=="nginx"        → 0
```

**Why `title`/`server` are 0 on central v1 — an honest dataset fact, not
a broken parser.** The engine's title/server path is proven by the
deterministic query-matrix tests (rows with HTTP evidence match). Central
dataset v1 carries NO HTTP metadata: the pipeline's observation step is a
TLS `:443` handshake (evidence keys `tls`+`scan` only; `title`/`server`
keys appear in 0 of 269 records). Zero results here mean "no evidence",
never "filter silently ignored" — an unknown FIELD is a loud
`GQL_E_FIELD` error, never an empty result.

## 6. Compatibility layer (additive)

### Boolean operators

| Form | Meaning |
| --- | --- |
| `&&` / `and` | logical AND |
| `\|\|` / `or` | logical OR |
| `!` / `not` | negation |
| `( … )` | grouping — parentheses have the highest priority |
| `=` | sugar for `==` |
| `==`, `!=`, `<`, `<=`, `>`, `>=` | comparison |
| `*=` | **wildcard fuzzy match**: `*` = any run of characters, `?` = exactly one |

Example: `(title="Admin" || product="OpenSSH") && port<1000`

`*=` is case-insensitive and escapes the SQL LIKE metacharacters, so
`server*="100%_uptime*"` matches the literal text `100%_uptime` plus
any suffix.

### Bare-keyword (free-text) search

A **quoted** keyword with no field searches the stored text surfaces of
the index — one OR-chain per term, AND across terms:

    gseer search '"wordpress"'
    gseer search '"apache" "login"'

The free-text field list (fixed, no configuration):

`asset_value`, `hostname`, `domain`, `http.title`, `http.server`,
`product`, `name`, `asn_org`, `tls.cert_subject_cn`, `tls.cert_issuer_cn`

Two deliberate exclusions, per the Search ≠ Scan architecture:

- **page body / headers / icons / JS** are not fetched or indexed by
  GSEER — a bare keyword never matches them because that data is not
  in the index;
- `ip` keeps exact-value semantics — use `ip *= "203.0.113.*"` for
  pattern matching.

An **UNQUOTED** bare word that is NOT a known field is free text
too — `gseer search 'nginx'` searches the same surfaces as
`gseer search '"nginx"'` (v0.3.2). A bare KNOWN field stays the
presence test — `gseer search 'hostname'` is the `exists(hostname)`
form; use `exists(field)` explicitly for presence tests.

### Field aliases

| Alias | Canonical field | Example |
| --- | --- | --- |
| `host` | `hostname` **or** `ip` | `host="203.0.113.10"`, `host*="www.example."` |
| `org`, `organization` | `asn_org` | `organization contains "Telecom"` (v0.3.2) |
| `base_protocol` | `transport` | `base_protocol="udp"` |
| `status_code` | `http.status` | `status_code=200` |
| `cert.subject.cn`, `cert.subject` | `tls.cert_subject_cn` | `cert.subject="example.com"` (v0.3.2) |
| `cert.issuer.cn`, `cert.issuer` | `tls.cert_issuer_cn` | `cert.issuer="R3"` (v0.3.2) |
| `cert.sn`, `cert_sn` | `tls.cert_serial` | `cert.sn="04f2a9c1de7b"` (v0.3.2) |
| `cert.domain`, `cert_domain` | `tls.cert_sans_dns` | `cert.domain contains "example.com"` (v0.3.2) |
| `country`, `region`, `city` | `geo_country`, `geo_region`, `geo_city` | `country="id"` |
| `app` | `product` | `app="nginx"` (v0.3.2 compat) |
| `ip_country`, `ip_region`, `ip_city` | `geo_country`, `geo_region`, `geo_city` | `ip_country="id"` (v0.3.2 compat) |
| `ip_after`, `ip_before` | `after`, `before` | `ip_after="2026-01-01"` (v0.3.2 compat) |
| `status`, `title`, `server` | `http.status`, `http.title`, `http.server` | `title*="Port?l"` |
| `tech`, `fingerprint` | `technologies` | `tech contains "wordpress"` |
| `cert_subject`, `cert_issuer` | `tls.cert_subject_cn`, `tls.cert_issuer_cn` | |
| `tls_version` | `tls.version` | |
| `cert_expiry` | `tls.cert_expiry` | |

### Time filters

| Field | Lowers to | Example |
| --- | --- | --- |
| `after`, `ip_after` | `last_seen >= date` | `after="2026-01-01"` |
| `before`, `ip_before` | `last_seen <= date` | `before="2026-01-01"` |
| `cert.not_after.after` | `tls.cert_expiry >= date` | certificates expiring after the date |
| `cert.not_after.before` | `tls.cert_expiry <= date` | certificates expiring before the date |

Values accept `"2006-01-02"` (calendar date, midnight UTC) or full RFC
3339 timestamps. On the personal (SQLite) engine every time comparison
normalizes BOTH sides through the `gseer_ts` registered function, so a
user-written `"2026-01-15T00:00:00Z"` compares chronologically against
the fixed-width micro storage format.

### Empty-value and presence semantics

| Query | Matches |
| --- | --- |
| `field=""` | rows where the field is missing **or** empty |
| `field!=""` | rows where the field is present **and** non-empty |
| `exists(field)` / bare `field` | rows where the field is not NULL |

Missing text/geo values are stored EMPTY (not NULL) on both engines, so
`! (country="US")` matches rows with no geo evidence too.

### Derived boolean fields

Computed predicates — no dedicated column, no extra data:

| Field | Meaning |
| --- | --- |
| `is_domain="true"` / `"false"` | the row carries a domain value / does not |
| `is_ipv6="true"` / `"false"` | IPv6 address / IPv4 address |
| `cert.is_expired="true"` / `"false"` | certificate expiry before / after now |

## 7. Performance notes (measured)

- The planner compiles to parameterized SQL with keyset cursor
  pagination; the default sort is `last_seen DESC` with a
  `(row_id, row_kind)` tiebreaker — pages are stable across pages.
- At 30k assets / 90k services (throwaway load-test rows, TEST-NET /
  RFC 1918 addresses only, dropped after measuring), a complex
  compound query (`port=443 && protocol="https" && (country="US" ||
  country="DE")`) plans to an **Index Scan** on
  `services_asset_port_transport_unique` plus an asset join —
  2.7 ms total on PostgreSQL 17 (migration 0004's indexes; EXPLAIN
  evidence in the release kit). A broad `port=443` at 2/90k
  selectivity stays a sequential scan under the plain-view design —
  the known, documented v0.0.1 trade-off (0003: the view definition IS
  the normative contract; a maintained backing table is the contained
  future performance option).
- On the personal (SQLite) engine the search_index view materializes
  its helper projections per query through `ix_observations_service` /
  `ix_observations_asset` (EXPLAIN QUERY PLAN evidence in the release
  kit).

## 8. Intentional divergences (honest differences)

1. **Typed, with one coercion**: integer fields take bare integers
   (`port=443`). A QUOTED integer is coerced in place for
   compatibility — `port="443"` and `port IN (80, "443")` behave
   exactly like their bare forms; a quoted non-numeric value
   (`port="https"`) stays a type error with the rewrite hint.
2. **`=` is exact, not fuzzy**: GQL `=` and `==` are both exact
   equality. Fuzzy matching is `*=` with explicit wildcards — nothing
   matches by accident.
3. **No body/header/icon/JS/hash fields** (`body`, `header`, `icon_hash`,
   `js_md5`, `cname`, `banner`, `jarm`, `ja3s`, `sdk_hash`,
   …): GSEER indexes **facts it is given** (Search ≠ Scan). It does not
   crawl or store page content, so fields over fetched content do not
   exist. The closest stored-surface equivalents are `http.title`,
   `http.server`, `tls.*`, `technologies` — and `cert.sn` / `cert.domain`
   ARE searchable since v0.3.2 (the TLS observer captures the leaf
   certificate; migration 0021/0005 projects serial + SAN DNS).
4. **No third-party-maintained metadata fields** (`app`-style vendor
   rules by name, aggregated site fingerprint IDs, categories, cloud /
   fraud / honeypot labels, dedicated-IP aggregates like
   `port_size_gt`, `ip_filter()`, `ip_exclude()`): these require a hosted
   aggregation backend or data sets GSEER does not license. The v0.3.2
   IP-aggregation compat ALIASES that map onto real stored fields
   (`ip_country/ip_region/ip_city/ip_after/ip_before`) are supported;
   the aggregate functions are not. Local equivalents: `technologies
   contains "…"` over the local fingerprint rule set (`gseer rules`).
5. **`host` alias vs `host` scope**: `host=` in a comparison is the
   `hostname` alias; `ANY(host){ … }` remains the host-level
   quantifier. The two never collide (one is an operator position, the
   other a scope position).

See `gseer search --help` for the live field registry and the normative
grammar (SPEC-04).
