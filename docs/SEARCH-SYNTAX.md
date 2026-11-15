# GSEER Search Syntax — Compatibility Guide

GSEER's query language (GQL) is specified in SPEC-04 §3. This document
describes the **compatibility layer**: additional operator spellings,
field aliases, and convenience forms that GQL accepts so queries
written in the *common asset-search style* used by other engines work
without translation. Everything here is additive — every query that was
valid before the compatibility layer stays valid, byte for byte.

## Boolean operators

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

## Bare-keyword (free-text) search

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

## Field aliases

| Alias | Canonical field | Example |
| --- | --- | --- |
| `host` | `hostname` **or** `ip` | `host="203.0.113.10"`, `host*="www.example."` |
| `org` | `asn_org` | `org contains "Telecom"` |
| `base_protocol` | `transport` | `base_protocol="udp"` |
| `status_code` | `http.status` | `status_code=200` |
| `cert.subject.cn` | `tls.cert_subject_cn` | `cert.subject.cn="example.com"` |
| `cert.issuer.cn` | `tls.cert_issuer_cn` | `cert.issuer.cn="R3"` |
| `cert.sn`, `cert_sn` | `tls.cert_serial` | `cert.sn="04f2a9c1de7b"` (v0.3.2) |
| `cert.domain`, `cert_domain` | `tls.cert_sans_dns` | `cert.domain contains "example.com"` — the SAN DNS entries as comma-joined text (v0.3.2) |
| `country`, `region`, `city` | `geo_country`, `geo_region`, `geo_city` | `country="id"` |
| `app` | `product` | `app="nginx"` (v0.3.2 compat) |
| `ip_country`, `ip_region`, `ip_city` | `geo_country`, `geo_region`, `geo_city` | `ip_country="id"` (v0.3.2 compat) |
| `ip_after`, `ip_before` | `after`, `before` | `ip_after="2026-01-01"` (v0.3.2 compat) |
| `status`, `title`, `server` | `http.status`, `http.title`, `http.server` | `title*="Port?l"` |
| `tech`, `fingerprint` | `technologies` | `tech contains "wordpress"` |
| `cert_subject`, `cert_issuer` | `tls.cert_subject_cn`, `tls.cert_issuer_cn` | |
| `tls_version` | `tls.version` | |
| `cert_expiry` | `tls.cert_expiry` | |

## Time filters

| Field | Lowers to | Example |
| --- | --- | --- |
| `after`, `ip_after` | `last_seen >= date` | `after="2026-01-01"` |
| `before`, `ip_before` | `last_seen <= date` | `before="2026-01-01"` |
| `cert.not_after.after` | `tls.cert_expiry >= date` | certificates expiring after the date |
| `cert.not_after.before` | `tls.cert_expiry <= date` | certificates expiring before the date |

Values accept `"2006-01-02"` (calendar date, midnight UTC) or full RFC
3339 timestamps.

## Empty-value and presence semantics

| Query | Matches |
| --- | --- |
| `field=""` | rows where the field is missing **or** empty |
| `field!=""` | rows where the field is present **and** non-empty |
| `exists(field)` / bare `field` | rows where the field is not NULL |

## Derived boolean fields

Computed predicates — no dedicated column, no extra data:

| Field | Meaning |
| --- | --- |
| `is_domain="true"` / `"false"` | the row carries a domain value / does not |
| `is_ipv6="true"` / `"false"` | IPv6 address / IPv4 address |
| `cert.is_expired="true"` / `"false"` | certificate expiry before / after now |

## Intentional divergences (honest differences)

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
