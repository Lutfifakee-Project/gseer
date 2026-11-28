// GSEER — internet-asset search engine.
// Copyright (C) 2026  The GSEER Authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cli

// config_cmd.go — `gseer config show|validate` (R93 product
// configuration): transparent, validated configuration without secrets.
// The engine config contains no credentials by design (personal mode
// embeds SQLite; self-hosted DSN points at the operator's own PG setup),
// so `show` can print the resolved configuration verbatim.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// registerConfigCmd attaches `gseer config`.
func registerConfigCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show or validate the resolved engine configuration (R93)",
		Long: `Configuration transparency (R93).

  show      print the resolved configuration (defaults + overrides) as JSON
  validate  load, validate, and probe the database connection (read-only)

Safe changes: the config file is edited by the operator; these commands
NEVER write it.  Upgrade compatibility: unknown keys are preserved, and
` + "`gseer config validate`" + ` is the safe post-upgrade check.`,
	}
	cmd.AddCommand(configShowCmd(), configValidateCmd())
	root.AddCommand(cmd)
}

func configShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the resolved configuration as JSON",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			cfg, err := engineConfigOrInit(cmd)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return enc.Encode(cfg)
		},
	}
}

func configValidateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration and probe the database connection",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			cfg, err := engineConfigOrInit(cmd)
			if err != nil {
				printf(out, "INVALID: %s\n", err.Error())
				exitWith(ExitConfig)
				return nil
			}
			if cfg.Profile != config.ProfilePersonal {
				_ = runConfigValidateSelfHosted(out, cfg)
				return nil
			}
			printf(out, "[ ok  ] configuration parses (profile %q, dsn %q)\n", cfg.Profile, cfg.Database.DSN)
			ctx, cancel := context.WithTimeout(commandContext(cmd), 10*time.Second)
			defer cancel()
			db, oerr := sql.Open("sqlite", cfg.Database.DSN)
			if oerr != nil {
				printf(out, "INVALID: database %s\n", oerr.Error())
				exitWith(ExitConfig)
				return nil
			}
			defer func() { _ = db.Close() }()
			if perr := db.PingContext(ctx); perr != nil {
				printf(out, "INVALID: database unreachable: %s\n", perr.Error())
				exitWith(ExitConfig)
				return nil
			}
			var version int
			if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err == nil {
				printf(out, "[ ok  ] database reachable, schema v%d\n", version)
			} else {
				if _, merr := sqlite.Migrate(ctx, db); merr != nil {
					printf(out, "INVALID: migrations: %s\n", merr.Error())
					exitWith(ExitConfig)
					return nil
				}
				printf(out, "[ ok  ] database reachable, migrations applied\n")
			}
			printf(out, "Configuration valid.\n")
			return nil
		},
	}
}

var _ = fmt.Sprintf // keep fmt for future structured messages
