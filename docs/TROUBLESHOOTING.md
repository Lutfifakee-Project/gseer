# GSEER — Troubleshooting

Common symptoms, what they mean, and how to recover.  Every command has
`--help`; `gseer doctor` checks the installation state read-only.

| Symptom | What it means / what to do |
| --- | --- |
| `commit: unknown` / `built_at: unknown` in `gseer version` | Normal for `go install` builds — module downloads carry no VCS metadata. The version is still correct; release binaries carry both fields. |
| `E_CONFIG_REQUIRED: database.dsn …` | No config anywhere and the command bypassed the zero-config path. Run `gseer setup` (provisions personal mode + writes the config). |
| `E_SOURCE_TERMS` when enabling/running a source | That connector's provider terms are not cleared for automated collection (`docs/SOURCES.md`). This is a policy gate, not a bug. |
| `E_QUERY_*` on search/facets | The GQL did not validate. The error names the position and a `Try:` fix; `gseer search '<q>' --validate` checks without touching the DB. |
| Doctor reports `HINT index: EMPTY` | Normal before the first data import. Run `gseer setup` (bootstrap + dataset import), or register a source and run `gseer collect run`. |
| `[skip ] context: egress IP undetectable` during setup | The egress echo did not answer (offline?). Nothing was guessed — register a source manually with `gseer source add`. |
| `E_DATASET_CHECKSUM` on setup/dataset update | The downloaded dataset payload did not match its manifest — the import is refused and the database is untouched. Retry `gseer dataset update` (a fresh read succeeds once the release channel is consistent). |
| `[warn ] dataset: …` during setup | The dataset channel was unreachable. Setup continues with your local bootstrap; run `gseer dataset update` later. |
| `E_SCOPE_DENIED` on `scan` | No live scope covers the target/protocol/port — register one with `gseer scope add`. Denials never touch the network. |
| `E_DB_BACKUP: …` | The backup target must differ from the live database file. |
| Migration failed mid-setup | `gseer db migrate status`, then `gseer db migrate diagnose`; `force` exists for recovery and asks for confirmation. |

## Backup, uninstall, start-over

```bash
gseer db backup --out ~/gseer-backup.db   # 1. take a snapshot first
rm "$(command -v gseer)"                  # 2. remove the binary (GOPATH/bin)
rm -rf ~/.gseer                           # 3. remove data + config (this deletes your index!)
```

To start over but keep your data: keep `gseer.db`, delete only
`~/.gseer/config.yaml`, and run `gseer` again — it re-initializes around
the existing database.

To move to another machine: copy `gseer.db` (and `config.yaml`), done.
