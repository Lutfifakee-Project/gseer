# Custom dataset import (`gseer import`) — format reference (R58)

`gseer import` loads a LOCAL dataset file into the search index through the
same Fact path every collector uses (same validators, same suppression gate,
same provenance). It never contacts the network.

## Formats

| Extension | Shape |
| --- | --- |
| `.csv` | header row + records (RFC 4180) |
| `.json` | a JSON array of objects |
| `.jsonl` / `.ndjson` | one JSON object per line |

Override with `--format csv|json|jsonl`.

## Field mapping

`--map target=column` (repeatable). Targets: `ip`, `domain`, `hostname`,
`asn`, `asn_org`, `country`, `port`, `protocol`. Unmapped targets default to
same-named columns when present. Every row needs ONE asset identity; a
non-IP value in the `ip` column that contains a dot is normalized to a
hostname. Unmapped columns are preserved under `evidence.custom` (visible in
`gseer host --history` timelines and exports; they are not dynamic query
fields in this release).

## Guarantees

- **Validation**: invalid rows are reported with their input line number and
  skipped (import continues).
- **Deduplication**: the delivery identity is `(source_id, "row:<line>")`
  plus a payload hash — re-importing the same file inserts nothing new.
- **Provenance**: source name (prefixed `custom-`), provenance `custom`,
  attribution note from `--attribution`.
- **Preview**: `--dry-run` validates and previews without writing.
- **No schema corruption**: custom data rides the standard asset/service/
  observation tables; no dynamic columns are created.

## Examples

    gseer import --file hosts.csv --name my-assets --dry-run
    gseer import --file hosts.csv --name my-assets \
        --map ip=address --map port=port --map protocol=proto \
        --attribution "Internal telemetry, internal use only"
