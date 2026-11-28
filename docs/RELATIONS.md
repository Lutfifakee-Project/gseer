# Infrastructure relationships (`gseer relations`) — R76/R77

Evidence-based relationship discovery around one asset. Every edge is a
SQL join over a maintained evidence projection (`latest_dns_t`,
`latest_ip2asn_t`, `latest_ctlog_t`, `latest_tls_t`,
`latest_fingerprints_t`, `assets`, `services`) and carries the
`observed_at` + source it was derived from. Nothing is inferred beyond
what your collectors recorded, and no separate graph database is used —
edges exist only where evidence exists (measured: 250 ms for the full
fan-out on the 1.09 GB corpus; a materialized edge table, not a graph DB,
is the documented next step if this ever dominates latency).

## Kinds

| Kind | Meaning | Evidence |
| --- | --- | --- |
| dns_resolves_to | hostname/domain → recorded A/AAAA/CNAME/MX answers | latest_dns_t |
| dns_reverse | IP ← other names whose DNS record mentions it | latest_dns_t |
| asn_origin | IP → ASN / organization / prefix attribution | latest_ip2asn_t + assets |
| prefix_peer | IP ↔ other assets under the same announced prefix | latest_ip2asn_t |
| cert_ct | domain/hostname → CT-log certificate | latest_ctlog_t |
| cert_ct_shared | domain ↔ other names on the same CT leaf certificate | latest_ctlog_t |
| cert_tls | service → TLS certificate (subject/serial/version) | latest_tls_t |
| cert_tls_shared | service ↔ SAN names of the same TLS certificate | latest_tls_t |
| same_org | asset ↔ other assets under the same ASN organization | assets |
| service | asset → services (port/protocol/product) | services |
| technology | service → fingerprinted technologies | latest_fingerprints_t |

## Usage

    gseer relations <asset-value>                # all kinds, per-kind cap 10
    gseer relations <asset-value> --kind cert_ct_shared
    gseer relations <asset-value> --format json|csv
    gseer fields          # every searchable field from the LIVE registry (R79)
    gseer examples        # runnable GQL examples (R79)

Strictly read-only; search ≠ scan is untouched (no network contact).
