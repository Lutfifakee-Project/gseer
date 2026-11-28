# GSEER — Passive Data Source Review Register

> v0.0.2 Passive Intelligence (owner directive §2).  This document is the
> review register every connector's `Review()` verdict anchors to.  A
> connector may only carry the verdict `reviewed-enabled` when the
> provider's terms clearly permit automated collection AND indexing of
> the retrieved data; everything else ships `disabled` — the runner
> refuses it (`E_SOURCE_TERMS`) even if a database row says enabled.
>
> Review date: 2026-11-03.  Providers change terms; re-review before
> flipping any verdict, and after any provider policy update.

## Verdict summary

| Connector | Provider | Verdict | One-line reason |
| --- | --- | --- | --- |
| `dns` | operator-configured resolver (system default) | **reviewed-enabled** | standard DNS recursion; the operator names every target; answers are protocol facts |
| `ip2asn` | Team Cymru IP-to-ASN (DNS interface) | **reviewed-enabled** | explicitly free community service; DNS interface requested "at volume"; conservative rates + caching |
| `ptr` | operator-configured resolver (system default) | **reviewed-enabled** | standard reverse-DNS (PTR) recursion; same basis as `dns` — operator-named addresses, protocol facts |
| `ctlog` | public CT logs from the official log list (default: Cloudflare Nimbus2026) | **reviewed-enabled** (§G, Rev 14) | RFC 9162 mandates public `get-sth`/`get-entries`; seed-free tip-following read of a bounded window; certificates are public data; the log is the only endpoint touched |
| `egress-echo` | api.ipify.org (public HTTPS echo, bootstrap context probe only) | **reviewed-enabled** (§F) | one bounded request at setup; returns the caller's own public IP; free service without per-use terms restrictions; provenance `egress-echo` |
| central dataset | the project's scheduled pipeline over the reviewed-enabled connectors above (§C/§D/§E + scoped TLS observation of the seeds register) | **reviewed-enabled** (Rev 9) | rows produced ONLY by reviewed-enabled connectors; validated before publication (gseer-dataset validate) and re-validated at import; provenance preserved per record — `docs/DATASET.md` |
| `pdns` | public key-less passive-DNS-style datasets: HackerTarget hostsearch + Wayback Machine CDX (config `provider`) | **reviewed-enabled** (§J, v0.3.3) | free public interfaces, one query per operator-named seed, rate-capped; published hostname/resolution history recorded as publication facts with lookup time |
| `rdap` | RIR registration data (ARIN/RIPE NCC et al.) | **disabled** | terms do not grant indexing/redistribution; needs written authorization |
| `ct` | crt.sh (Sectigo CT aggregation) | **disabled** | no published terms covering automated collection or indexing/reuse |

Rejected outright (documented, no connector code), described by
rejection reason rather than by vendor — a rejected source is not part
of this product's data supply chain and is not advertised here:
BGP/aggregation dashboards whose HTML scraping may be banned without
notice and whose bulk API is a paid product; registry-data aggregators
whose T&C prohibit re-packaging, compiling and re-distributing the
data; commercial internet-wide scanning / hosted asset-search services
whose account + commercial terms do not grant indexing of derived data
into third-party search products.

---

## §A Certificate Transparency — crt.sh (connector `ct`)

1. **Source identity / endpoint**: crt.sh, operated by Sectigo Limited —
   https://crt.sh/ (JSON API: `https://crt.sh/?q=<name>&output=json`;
   direct PostgreSQL interface advertised for power users).
2. **Access method**: HTTP GET (JSON), plus an advertised public
   PostgreSQL endpoint (`crt.sh:5432`, user `guest`, db `certwatch`).
3. **API key requirements**: none.
4. **License / terms of use**: none published for the service or its
   data.  The site footer asserts "© Sectigo Limited … All rights
   reserved".  No licence for the aggregation is stated anywhere on the
   site (verified 2026-11-03).
5. **Permission for automated collection and indexing**: **not
   established**.  No terms document grants (or forbids) automated
   querying, caching, storing or re-publishing of the aggregation.
   Community tooling treats the JSON endpoint as open, but folklore is
   not permission.
6. **Rate limits**: none documented (the service is known to be
   slow/oversubscribed at times).
7. **Data retention**: not documented (the underlying certificate data
   is retained per CT log operator policy; crt.sh's own retention is
   unpublished).
8. **Privacy**: CT entries are public by design (RFC 6962/9162) and
   contain certificate fields (SANs, organization names) — no resolver
   or query-side data.
9. **Provenance**: Sectigo's aggregation over the public CT log ecosystem
   (certificates and precertificates submitted to publicly trusted logs).
10. **Freshness**: continuous ingestion from logs; visible lag is common
    (log batch timing, crt.sh backlog).
11. **Known limitations**: duplicate entries per cert (multi-log),
    precertificate/certificate duplication, wildcard names need
    normalization, no liveness or IP data, CT only covers
    publicly-trusted certificates.
12. **Verdict: `disabled`** — unclear permission for indexing/reuse
    (owner directive §2: keep disabled).  The connector is implemented
    and unit-tested; flipping `Review()` is a one-line, owner-visible
    change after the terms question is settled (or after switching to a
    provider with explicit API terms — e.g. an account-based CT API with
    a written licence; noted for the owner, not actioned).

## §B RDAP — RIR registration data (connector `rdap`)

1. **Source identity / endpoint**: the five RIR RDAP services, discovered
   via the IANA bootstrap registries —
   https://data.iana.org/rdap/ipv4.json, …/ipv6.json, …/dns.json
   (RFC 9224); e.g. https://rdap.arin.net/registry/,
   https://rdap.db.ripe.net/.
2. **Access method**: HTTP GET (RFC 9082/9083 JSON), no auth.
3. **API key requirements**: none (anonymous per-query access).
4. **License / terms of use**: each RIR applies its own registration-data
   terms — ARIN: https://www.arin.net/resources/registry/whois/tou/;
   RIPE NCC data-service terms;
   APNIC/LACNIC/AFRINIC publish analogous whois/RDAP terms.
5. **Permission for automated collection and indexing**: **not granted
   for GSEER's use**.  ARIN's ToU permits querying for enumerated
   purposes (routing policy evaluation, operational coordination,
   reverse-DNS, own-business use *without republishing*, scientific
   research into network operations, abuse processing) and states:
   "Unless ARIN provides specific prior written authorization, no other
   use of the Whois Service other than as expressly described in these
   Terms is implied or permitted", with an explicit prohibition on
   making Whois-database data "publicly available" outside those uses,
   and a commercial-service prohibition.  RIPE NCC's terms prohibit
   re-packaging, compiling and re-distributing the data.  Indexing the
   answers into a GSEER search index is redistribution the terms do not
   grant.
6. **Rate limits**: RIR-specific, enforced ad hoc (ARIN asks courtesy
   rates; RIPE documents daily limits for its services).  Not uniform —
   one more reason the verdict is not "enabled".
7. **Data retention**: registry-defined; not GSEER-controllable.
8. **Privacy**: RDAP responses can contain registrant/abuse contact
   objects (organizations, role mailboxes).  GDPR-sensitive fields are
   redacted by the registries to varying degrees; redistribution of the
   non-redacted remainder is exactly what the terms restrict.
9. **Provenance**: the registries' own registration objects (networks,
   ASNs, organizations).
10. **Freshness**: registration data changes slowly; no change-feed
    guarantees on anonymous RDAP.
11. **Known limitations**: coverage differs per RIR; in-registry data
    quality varies; bootstrap file is updated independently of the RIRs.
12. **Verdict: `disabled`** — needs the provider's written authorization
    before GSEER may index the data.  The connector (IANA bootstrap →
    RIR lookup → country/name/handle/range enrichment) is implemented
    and unit-tested for the day the owner secures authorization.

## §C Public DNS — operator-domain resolution (connector `dns`)

Rev 14 (2026-11-27): the seed register grows from 14 to 26 domains — all
additions DNS-ONLY (passive resolution via public recursive resolvers;
none added to the active `tls_hosts` subset).  Per-entry terms basis is
documented in `pipeline/dataset-seeds.yaml`.

1. **Source identity / endpoint**: the DNS resolution system — the
   operator's configured resolver (default: the operating system's
   resolver; overridable per source via `resolver: host:port`).  GSEER
   deliberately does NOT hardcode any third-party resolver.
2. **Access method**: standard UDP/TCP 53 recursive queries (the same
   protocol every internet-connected system speaks).
3. **API key requirements**: none.
4. **License / terms of use**: DNS is a protocol, not a licensed
   dataset; recursive resolution is the resolver's normal purpose.
   Public resolver services publish acceptable-use expectations for
   standard usage — ordinary programmatic resolution is the service
   working as intended.  Operators who point GSEER at a specific
   public resolver are responsible for that provider's AUP; the
   default (system resolver) is the operator's own infrastructure.
5. **Permission for automated collection and indexing**: resolution
   answers (A/AAAA/CNAME/MX/NS records) are uncopyrighted protocol facts;
   GSEER records the factual answer with its lookup time.  Queries are
   bounded by the seed list — only names the operator configured or
   that are already in the operator's index are resolved.
6. **Rate limits**: self-imposed conservative caps (default client
   1 request/second; per-source `requests_per_second` /
   `limit_per_run`).  No third-party quota is consumed by default.
7. **Data retention**: GSEER keeps the answer as an asset fact with
   first_seen/last_seen (the index IS the cache); TTLs are honored by
   the resolver, not re-implemented.
8. **Privacy**: DNS queries reveal which names the operator resolves to
   the resolver operator — the standard privacy property of recursive
   DNS.  Using the default system resolver keeps that with the
   operator's own infrastructure.  Resolved data is about domains, not
   persons.
9. **Provenance**: `provenance = "dns"` on every observation; evidence
   carries the query name and record type.  The operator's seed itself
   is recorded as a first-class `domain` asset (confidence `high`) whose
   evidence carries the seed marker (`seed: {mode: …}`) and NO record
   type — the seed is the collection TARGET the operator named, not a
   record answer, and GSEER never presents it as one.  Every record
   answer about the seed carries the same canonical query name, so the
   seed ↔ resolved IP ↔ CNAME/MX/NS relationships stay queryable;
   collecting the same seed from several sources merges into ONE asset
   with unioned source provenance.
10. **Freshness**: the observation time IS the lookup time; re-running
    the connector ages last_seen forward (stale flag clears).
11. **Known limitations**: recursive answers may come from cache (hence
    confidence `medium`); negative answers (NXDOMAIN) are not facts and
    are not stored; MX/NS lookups are best-effort per seed (a lookup
    miss on a seed whose A lookup succeeded is ordinary DNS — an apex
    without MX is normal — and never fails the pass); TXT records are
    deliberately NOT collected (free-form strings with no typed,
    searchable column — collecting them would be evidence-only noise,
    not searchable observations); DNS data says nothing about
    reachability of services (discovery ≠ observation — no
    port/HTTP/TLS/banner data is invented).
12. **Verdict: `reviewed-enabled`** — clear terms (standard protocol,
    operator-named targets, self-imposed rates), no third-party
    dependency by default.

## §D ASN/BGP — Team Cymru IP-to-ASN (connector `ip2asn`)

1. **Source identity / endpoint**: Team Cymru's IP-to-ASN mapping
   community service — official page
   https://www.team-cymru.com/ip-asn-mapping; DNS interfaces
   `origin.asn.cymru.com` (IPv4), `origin6.asn.cymru.com` (IPv6), and
   `AS<n>.asn.cymru.com` (AS names); whois interface
   `whois.cymru.com` port 43 (bulk mode supported — GSEER uses the DNS
   interfaces only).
2. **Access method**: DNS TXT queries, one per identifier, plus one AS
   name lookup per hit.
3. **API key requirements**: none.
4. **License / terms of use**: published on the service page: "Free,
   forever.  IP to ASN mapping is part of Team Cymru's community
   services, underwritten by Team Cymru."  No redistribution licence is
   stated in terms; the answers are derived from the RIRs' public
   delegation data (routing publication facts: origin AS, prefix,
   country, registry, allocation date).
5. **Permission for automated collection and indexing**: the service is
   published FOR automated use — the page's stated expectation is that
   volume users take the bulk or DNS interface ("The only ask is that
   you use bulk mode or DNS at volume").  GSEER uses the DNS interface
   (the lighter one), answers are cached in the index (each identifier
   is asked once, then ages via last_seen), and runs are capped by
   `limit_per_run`.
6. **Rate limits**: no numeric quota published for the DNS interface;
   GSEER self-imposes the client default (1 req/s) and a per-run budget.
   The bulk interface exists precisely for higher volumes — if GSEER
   ever needs more, switching to documented bulk mode is the
   terms-compliant path.
7. **Data retention**: not documented; answers are point-in-time
   routing data retained by GSEER with observation timestamps.
8. **Privacy**: AS/prefix answers are network facts; no personal data.
   GSEER's queries reveal which IPs the operator enriches (standard
   DNS-protocol property; queries go to Team Cymru's authoritative
   servers).
9. **Provenance**: `provenance = "ip2asn"`; evidence keeps the raw TXT
   line, prefix, registry and allocation date; ASN/AS-name/country land
   in the asset's typed columns.
10. **Freshness**: routing data is point-in-time (`confidence:
    medium`); re-runs refresh last_seen.
11. **Known limitations**: the DNS interface does not vouch for live
    routing state at query time; multi-origin (MOAS) prefixes return
    one answer line (the first); AS-name parse is defensive — an
    unexpected format degrades to an empty name without blocking the
    ASN enrichment.
12. **Verdict: `reviewed-enabled`** — explicitly free community service
    published for this access method, conservative self-limits, cached
    answers.

## §E Reverse DNS — PTR records (connector `ptr`)

1. **Source identity / endpoint**: the DNS resolution system — the
   operator's configured resolver (default: the operating system's
   resolver; overridable per source via `resolver: host:port`),
   querying the standard `in-addr.arpa` / `ip6.arpa` reverse trees.
   GSEER deliberately does NOT hardcode any third-party resolver.
2. **Access method**: standard UDP/TCP 53 recursive PTR queries (the
   same protocol, and the same resolver, as the `dns` connector).
3. **API key requirements**: none.
4. **License / terms of use**: identical basis to §C — DNS is a
   protocol, not a licensed dataset; reverse resolution is the
   resolver's normal purpose.  Operators who point GSEER at a specific
   public resolver are responsible for that provider's AUP; the
   default (system resolver) is the operator's own infrastructure.
5. **Permission for automated collection and indexing**: PTR answers
   are uncopyrighted protocol facts (a name published for an address
   by its operator, via the address's delegation).  Queries are
   bounded by the seed list — only addresses the operator configured
   or that are already in the operator's index are resolved.  NO CIDR
   sweeps, NO neighbor enumeration: a seed list of one address is one
   query.
6. **Rate limits**: self-imposed conservative caps (default client
   1 request/second; per-source `requests_per_second` /
   `limit_per_run`).  No third-party quota is consumed by default.
7. **Data retention**: GSEER keeps the answer as a hostname sighting
   with first_seen/last_seen (the index IS the cache).
8. **Privacy**: reverse queries reveal which addresses the operator
   enriches to the resolver operator — the standard privacy property
   of recursive DNS, kept with the operator's own infrastructure by
   default.  PTR answers are about host naming, not persons.
9. **Provenance**: `provenance = "ptr"` on every observation; evidence
   carries the queried address and the raw answer name.
10. **Freshness**: the observation time IS the lookup time; re-running
    the connector ages last_seen forward (stale flag clears).
11. **Known limitations**: many addresses publish no PTR record (the
    empty answer is a non-fact and is not stored); recursive answers
    may come from cache (confidence `medium`); a PTR name says nothing
    about reachability of services (discovery ≠ observation — no
    port/HTTP/TLS/banner data is invented).
12. **Verdict: `reviewed-enabled`** — clear terms (standard protocol,
    operator-named targets, self-imposed rates), no third-party
    dependency by default.  Introduced in v0.3.0.

## Rejected / not implemented (watch list)

Rejection reasons are recorded by category, not by vendor name — the
rejected services stay out of this product's supply chain, and the
factual reasons below are what matters for any future re-review:

- **BGP/aggregation dashboards with contract-only bulk access** — HTML
  scraping may be banned with no notice; the bulk API is a paid
  product.  No connector.  Revisit only with a contract.
- **Registry-data aggregators with no-redistribution T&C** — the terms
  prohibit re-packaging, compiling and re-distributing the data;
  commercial derivative use needs written permission.  Indexing into
  GSEER is redistribution risk.  No connector.
- **Commercial internet-wide scanning / hosted asset-search services** —
  account/API-key required; free-tier terms do not grant indexing of
  derived data into third-party search products.  No connector.
- **Commercial passive-DNS databases** — API keys required and
  derived-data terms are restrictive.  No connector.
- **Account-based certificate-transparency APIs** — the free tier
  requires signup and hourly query caps; commercial API terms.  A
  viable fallback if the owner accepts account-based access; not
  actioned.


## §F Egress context echo — api.ipify.org (bootstrap context probe)

- **Provider / endpoint:** `https://api.ipify.org` (public HTTPS echo).
- **What it returns:** the caller's own public IP address — nothing else.
- **Why the bootstrap needs it:** with the shared-index channel removed
  (v0.3.2 CLI-only architecture), `gseer setup` seeds local passive
  discovery from the operator's own egress context.  The echo supplies
  the IP; PTR (§E) names it; the public-suffix list derives the
  registrable domain that seeds `dns` (§C).
- **Verdict basis:** a single bounded HTTPS GET at setup time (15 s
  budget), no account, no API key, no per-use restriction in the
  provider's published terms; the data retrieved is the operator's own
  address, so indexing it raises no third-party-terms concern.  The
  response is recorded with provenance `egress-echo` in the setup
  output, never as an index fact on its own.
- **Failure mode:** offline or unreachable echo ⇒ an honest `[skip]`
  and a manual `gseer source add` pointer.  Nothing is guessed.
- **Re-review triggers:** any change to the provider's terms, any move
  of the echo endpoint, or any expansion of what the bootstrap queries
  from it.

## §G CT log walking — public Certificate Transparency logs (connector `ctlog`, Rev 14)

- **Provider / endpoint:** any log from the official public log list
  (`https://www.gstatic.com/ct/log_list/v3/log_list.json`); the connector
  defaults to Cloudflare's Nimbus 2026 log
  (`https://ct.cloudflare.com/logs/nimbus2026/`).  Operators select a
  different list entry with `gseer source add --endpoint`.
- **What it does:** speaks the RFC 6962/9162 protocol DIRECTLY to the log —
  `get-sth` for the tree size, `get-entries` for a bounded window of the
  FRESHEST entries per run — and records every DNS name the contained
  X.509 certificates cover (SANs; wildcard `*.name` collapses to its base
  name).  No operator seeds are involved: this is the project's first
  SEED-FREE discovery source, and the only pipeline step whose coverage
  grows beyond the seed register by itself.
- **Terms basis (why this is `reviewed-enabled` where §A is not):** the
  permission is the protocol itself, not a provider licence page.
  RFC 9162 §5 requires every log to serve `get-entries`/`get-sth`
  publicly — public audit access is the log's designed purpose; the log
  list is a published public directory; the underlying certificates are
  public artifacts (they travel inside every TLS handshake to any
  client).  Read-only HTTPS GETs, bounded (default 128 entries per
  request — far under the RFC's 1000 cap — and `limit_per_run` entries
  per run), rate-limited by the shared passive client (1 req/s default).
- **What it never does:** no contact with a discovered domain (discovery ≠
  observation — port/service facts stay reserved to explicit, scoped
  `gseer scan` runs); no account, no API key, no query patterns tied to
  any target list; no crt.sh aggregation (§A stays disabled).
- **Provenance per fact:** the log URL, the absolute entry index, the
  SHA-256 of the raw log leaf (cryptographic evidence), the CT log's own
  timestamp, the certificate issuer and validity window; `observed_at` is
  the honest fetch time.  `confidence: high`.
- **Freshness / growth:** each run tip-follows the log (start =
  max(cursor+1, tip − limit)); consecutive runs never gap and overlaps
  dedupe at the delivery identity (L1), so the dataset grows with the
  freshest certificates instead of re-walking a static list.
- **Known limitations:** CT only covers publicly-trusted certificates; no
  IP/service data (names only — DNS resolution of discovered names is the
  `dns` connector's separate, terms-reviewed job); pre-certificates and
  RFC 9162 v2 leaves are skipped honestly (counted in the run stats);
  names are sightings, not liveness.
- **Verdict: `reviewed-enabled`** (Rev 14, owner-scoped).  Re-review
  triggers: any log operator's terms change that restricts public read
  access, a move off the official log list, or any attempt to raise the
  read volume beyond the bounded window.
- **Watch-list note:** the "account-based certificate-transparency APIs"
  fallback below remains unnecessary for seed-free discovery — direct
  log walking (this section) needs no account.  It stays recorded for
  identity-scoped CT search if the owner ever wants it.



## §H Public domain-popularity lists — Majestic Million (connector `topdomains`, R39)

- **Source identity:** the Majestic Million — the top million domains by
  referring subnets, published by Majestic (majestic.com) as a free CSV
  download: `https://downloads.majestic.com/majestic_million.csv`.
- **License / terms:** the file is published for free public download
  ("You are free to use this data...") per Majestic's Majestic Million
  terms page (https://majestic.com/reports/majestic-million).  GSEER
  ingests the file verbatim at runtime; it attributes the source in
  every evidence object (`topdomains.attribution`) and does not
  redistribute the file itself inside the source kit.
- **Verdict:** reviewed-enabled.  The operator ingests a list the
  publisher distributes for exactly this purpose; no authentication, no
  scraping, one polite request per run.
- **Snapshot honesty:** the list is a periodic AGGREGATE.  There is no
  per-record timestamp upstream — GSEER records the fetch time as
  `observed_at` and never claims the domain was "observed live".  The
  published numbers (rank, RefSubNets, RefIPs) are copied verbatim into
  evidence, not re-measured.
- **Freshness / incremental:** line-offset checkpoint (`topdomains`
  cursor) — a run that hits its record budget resumes at the line
  offset; the freshness contract is operator-driven re-runs.
- **Failure handling:** parse-invalid rows are counted
  (`skipped:invalid`), never fabricated into facts; a transport failure
  fails the attempt honestly.
- **Downstream:** the ingested domains are first-class domain assets —
  the corpus the DNS connector (`seed_mode index`) resolves A/AAAA/
  CNAME/MX/NS/TXT for (§C) and the CT/DNS relationship layer builds on
  (R39 P3/P5).  No Internet-wide scanning is involved anywhere.



## §I BGP RIB archives — RouteViews (connector `routeviews`, Rev 14)

- **Provider:** University of Oregon RouteViews Project — public BGP RIB
  dumps (routeviews.org), IPv4/IPv6, licensed CC BY 4.0 (attribution is
  embedded in the connector as `routeviewsAttribution` and travels on
  every fact as provenance evidence).
- **What it yields:** prefix → origin-AS mapping ("VRF default" view) as
  ASN-attribution facts for IP assets already in the index.  BGP/RIB
  evidence is ROUTING data, never a claim that a port or service is
  reachable (§D holds for the service layer).
- **Terms basis:** passive download of a public archive (plain HTTPS
  GET of the MRT dump), attribution preserved, no contact with the
  prefixes described, rate and size bounded (`routeviewsDefaultLimit`
  prefix facts per run, checkpointed cursor).
- **MOAS / IPv6:** multi-origin sets are recorded as separate facts with
  the snapshot timestamp; IPv6 prefixes follow the same path as IPv4.
- **Snapshot freshness:** every fact carries the RIB file timestamp it
  was derived from — the consumer sees the routing epoch, not the import
  time.
- **Status (Rev 14 / v0.3.2):** `reviewed-enabled` at the connector
  level, but NOT scheduled in the 6-hour dataset pipeline: a full RIB is
  a large artifact and the dataset payload cap (512 MiB) is reserved for
  the discovery channel.  The owner runs it on demand
  (`gseer source add rv --type routeviews …` + `gseer collect run --source rv`)
  or in a separate lower-frequency workflow when ASN coverage growth is
  wanted.  This register entry is what unblocks that run.

## §J Passive DNS — published hostname/resolution history (connector `pdns`, v0.3.3)

- **Sources (config `provider`):**
  - `hackertarget` (default) — the HackerTarget hostsearch API
    (`https://api.hackertarget.com/hostsearch/?q=<domain>`), a free,
    key-less, rate-limited public interface answering
    "hostname,address" lines for a queried domain.
  - `wayback` — the Internet Archive Wayback Machine CDX index
    (`https://web.archive.org/cdx/search/cdx?url=*.domain&output=json`),
    the public archive of crawled URLs; every archived URL's hostname is
    name-only evidence (the archive publishes what crawlers saw).
- **What it yields:** the HOSTNAMES published under operator-named
  domains — the historical layer the live `dns` connector (§C)
  complements.  HackerTarget's address lines ride in evidence; no
  service rows are ever produced (Discovery ≠ observation).
- **Verdict:** reviewed-enabled.  Both interfaces are free and
  key-less, the operator names every query (one per seed, config or
  index mode), the shared client caps rate and body size, and the
  shared-client user agent identifies GSEER.  Answers are recorded
  with their LOOKUP time (`observed_at` is when GSEER saw the
  publication, never the provider's historical time).
- **Snapshot honesty:** passive-DNS-style datasets are aggregates of
  third-party history.  GSEER records them as publication facts
  (confidence "medium"), never as live reachability, and the provider
  answers bound the facts (no guessing, no brute-force enumeration).
- **Failure handling:** a provider's free-tier quota message is an
  ERROR, never a hostname; one failed seed does not sink the others'
  answers (per-seed isolation), and all-failed is an honest error.
- **Downstream:** hostname assets feed the same index the DNS (§C),
  PTR (§E) and CT layers build on; cross-source duplication against
  those layers is visible in `gseer coverage`.

## How verdicts are enforced (architecture cross-reference)

- Every connector carries `Review()` (internal/collect/doc.go, contract 2);
  `collect.Runner.Run` refuses non-`reviewed-enabled` connectors with
  `E_SOURCE_TERMS` BEFORE opening a job row — a hand-flipped
  `enabled=true` database row cannot outrun it.
- `gseer source add --enable` and `gseer source enable` refuse at the
  CLI for the same reason.
- Registration stamps `data_sources.terms_ref` with the review reference
  so the registry row is self-describing.
- The unit test `TestBuiltinConnectorVerdicts` pins every verdict to this
  register — a verdict change without a register update fails CI.
