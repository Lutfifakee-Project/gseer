# Configuration (R93)

The resolved configuration is transparent and secret-free by design:

    gseer config show        # resolved config as JSON (defaults + overrides)
    gseer config validate    # parse + probe the database (read-only; safe post-upgrade)

Rules: the CLI never writes the config file; unknown keys are preserved on
upgrade; personal mode embeds SQLite (no DSN secrets) while self-hosted
mode points at the operator's own PostgreSQL setup.
