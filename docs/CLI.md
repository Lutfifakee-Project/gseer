# GSEER — CLI Reference

Every command carries its own full documentation: `gseer <command>
--help`.  This page is the command map.  Query language:
[`docs/SEARCH-SYNTAX.md`](SEARCH-SYNTAX.md).  Configuration and
environment variables: [`.env.example`](../.env.example).  Fresh-install
workflow: [`docs/QUICKSTART.md`](QUICKSTART.md).

## Command map

| Command | What it does |
| --- | --- |
| `gseer` (bare) | First run initializes personal mode automatically; later runs print an honest status panel |
| `gseer setup` | Prepare the search environment (personal mode: local bootstrap + central dataset import) |
| `gseer search '<GQL>'` | Search the configured index with GQL |
| `gseer status` | One informational view of the product state (binary, profile, database, discovery) |
| `gseer doctor` | Diagnose config, connectivity, database, and index health |
| `gseer source` | Manage registered data sources (passive connectors; nothing collects until you run it) — `add` / `enable` / `disable` / `list` |
| `gseer collect` | Run passive data connectors (explicit; nothing scans, nothing auto-runs) — `run` / `status` / `redrive` |
| `gseer dataset` | Central dataset channel — `update` / `check` / `status` |
| `gseer suppress` | Manage the suppression policy (exact IP/CIDR/domain/suffix/source rules) — `add` / `list` / `remove` |
| `gseer scope` | Manage the active-observation authorization registry (default-deny; nothing scans until you run `gseer scan`) — `add` / `list` / `revoke` / `audit` |
| `gseer scan` | Observe ONE explicitly authorized target (gateway-enforced; nothing scans without a scope) — `http` / `tls` |
| `gseer host` | Show everything GSEER knows about one host (read-only) |
| `gseer rules` | Manage fingerprint rules (technology classification over observed evidence) — `list` / `validate` |
| `gseer export` | Export search results as JSON, CSV, or NDJSON (streamed, cursor-stable) |
| `gseer db` | Database administration — `backup` / `restore` / `migrate` |
| `gseer update` | Verify and apply signed updates (signature → version → platform → checksum → atomic replace) |
| `gseer version` | Show version, commit, and build info |
| `gseer completion` | Generate the autocompletion script for the specified shell |

## Global flags

```text
      --config string    path to config file (default: $GSEER_CONFIG or platform default)
  -h, --help             help for gseer
      --no-color         disable color output
  -o, --output string    output format: table|json|yaml|csv|ndjson
      --profile string   configuration profile (personal | self-hosted)
      --quiet            quiet output (suppress tips and banners)
      --verbose          verbose output (include stack traces on error)
      --version          show version and exit
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success (including a zero-result search) |
| 1 | Generic error returned by a command's error path |
| 2 | Invalid query / invalid input (`E_QUERY_*`) |
| 3 | Configuration failure (`E_CONFIG*`, missing runtime credential) |
| 4 | Service unavailable (endpoint/DB/index; audit could not run) |
| 5 | Security/privilege refusal: failed privilege audit, runtime-credential identity mismatch |
| 64 | Usage error / planned-command pointer (`gseer asset`) |
| 70 | Internal error |

## Where to go next

- [`docs/QUICKSTART.md`](QUICKSTART.md) — canonical fresh-install walkthrough
- [`docs/INSTALL.md`](INSTALL.md) — install methods, checksums, build from source
- [`docs/SEARCH-SYNTAX.md`](SEARCH-SYNTAX.md) — GQL grammar, operators, field registry
- [`docs/SOURCES.md`](SOURCES.md) — data-source review register
- [`docs/SCANNING.md`](SCANNING.md) — authorized active observation and the scope gateway
- [`docs/TROUBLESHOOTING.md`](TROUBLESHOOTING.md) — common errors and recovery
