# Change detection & historical intelligence (R56/R57)

## Where history lives

The `observations` table is the historical evidence: append-only, one row
per collection with `observed_at`, `provenance`, `source_id` and the
payload. Raw history is retained until retention prunes it (`gseer db
retention`).

## Historical queries

    gseer host <value> --history        # observation timeline + detected changes
    gseer changes list --asset <value>  # change events for one asset
    gseer changes list --kind tls.cert --limit 50
    gseer changes list --since 2026-01-01T00:00:00Z --format csv

`--history` shows exactly what was observed and when — inferred history is
never displayed as fact.

## Change detection

    gseer changes detect           # incremental (processed-set marker)
    gseer changes detect --full    # full re-detect (idempotent)

An event is recorded ONLY when a projected value actually differs from the
previous observation's value: `dns.record`, `asn.prefix`, `ct.cert`,
`http.status/title/server`, `tls.version`, `tls.cert` (serial rotation),
`tech`, `banner`, plus first sightings (`asset.new`, `service.new`).
Routine refreshes of unchanged data emit NOTHING. Every event carries the
source and `observed_at` of the observation that revealed it. Re-running
detection can never duplicate events (UNIQUE tuple); a corrupt/missing
marker degrades to a safe full re-detect.

## Limitations (honest)

- Detection covers the tracked projections above; arbitrary JSON diffs are
  not classified as changes in this release.
- `gseer changes` / `import` / `preset` / `db retention` / `coverage` run on
  the personal (SQLite) store in this release; self-hosted (PostgreSQL)
  parity for these commands is documented as a known gap.

## Operational validation & maintenance (R81/R96)

    gseer selfcheck          # invariant checks: schema/integrity/consistency/projections/changes/presets
    gseer db maintenance     # freshness per source + marker verification + ANALYZE (--vacuum optional)

`selfcheck` exits non-zero when any invariant fails; see RECOVERY.md for
the repair playbook.  `db maintenance` never deletes data — retention
stays the explicit, dry-run-default command.
