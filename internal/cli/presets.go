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

// presets.go — `gseer preset` (R60 search workflow, CLI-first): named,
// reusable GQL queries stored in the local index (search_presets,
// migration 0014).  A preset is executed by the SAME SearchService — no
// new query semantics, no GUI, no network.  `gseer search --preset NAME`
// runs one; `gseer preset run NAME -- --format csv` keeps the standard
// search flags available.

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/gql/parser"
	"github.com/Lutfifakee-Project/gseer/internal/gql/validator"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// registerPresetCmd attaches `gseer preset add|list|rm`.
func registerPresetCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "preset",
		Short: "Manage saved queries (named GQL + sort + mode, local and private)",
		Long: `Save, list and run reusable search queries (R60).

A preset stores the GQL expression plus optional --sort and --mode; it is
validated at save time (the same parser/validator the search command uses),
stored LOCALLY in the personal index, and run through the same SearchService
— identical semantics, deterministic output, nothing leaves the machine.

Examples:
  gseer preset add nginx-443 'server == "nginx" && port == 443' --sort last_seen:desc
  gseer search --preset nginx-443 --limit 5
  gseer preset list
  gseer preset rm nginx-443`,
	}
	cmd.AddCommand(presetAddCmd(), presetListCmd(), presetRmCmd())
	root.AddCommand(cmd)
}

func openPresetDB(ctx context.Context, cmd *cobra.Command) (*sql.DB, func(), error) {
	cfg, cerr := engineConfigOrInit(cmd)
	if cerr != nil {
		return nil, nil, cerr
	}
	if cfg.Profile != "personal" {
		return nil, nil, fmt.Errorf("E_PROFILE_UNSUPPORTED: gseer preset runs on the personal (SQLite) store in this release")
	}
	res, oerr := openPersonal(cfg)
	if oerr != nil {
		return nil, nil, oerr
	}
	if _, merr := sqlite.Migrate(ctx, res.DB); merr != nil {
		_ = res.DB.Close()
		return nil, nil, merr
	}
	return res.DB, func() { _ = res.DB.Close() }, nil
}

// validatePresetGQL runs the same parse+validate pipeline the search
// command uses — a preset that would not compile is refused at save time.
func validatePresetGQL(cmd *cobra.Command, gql, sort, mode string) error {
	tree, err := parser.Parse(gql)
	if err != nil {
		return err
	}
	if _, err := validator.Validate(tree); err != nil {
		return err
	}
	return nil
}

func presetAddCmd() *cobra.Command {
	var fSort, fMode string
	cmd := &cobra.Command{
		Use:   "add <name> '<gql>'",
		Short: "Save a query as a named preset (validated at save time)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			name, gql := args[0], args[1]
			// Validate at save time: an unparsable preset is refused here,
			// not at 3am when someone runs it.
			if err := validatePresetGQL(cmd, gql, fSort, fMode); err != nil {
				printf(out, "E_PRESET_INVALID: %s\n", err.Error())
				exitWith(ExitInvalidInput)
				return nil
			}
			ctx := commandContext(cmd)
			db, closer, err := openPresetDB(ctx, cmd)
			if err != nil {
				return err
			}
			defer closer()
			now := time.Now().UTC().Format(time.RFC3339)
			_, err = db.ExecContext(ctx, `INSERT INTO search_presets (name, gql, sort, mode, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?)
				ON CONFLICT (name) DO UPDATE SET gql = excluded.gql, sort = excluded.sort,
				  mode = excluded.mode, updated_at = excluded.updated_at`,
				name, gql, fSort, fMode, now, now)
			if err != nil {
				return err
			}
			printf(out, "[ ok  ] preset %q saved (validated against the current field registry)\n", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&fSort, "sort", "", "default sort for this preset (e.g. last_seen:desc)")
	cmd.Flags().StringVar(&fMode, "mode", "", "default search mode: service|asset")
	return cmd
}

func presetListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List saved presets",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := commandContext(cmd)
			db, closer, err := openPresetDB(ctx, cmd)
			if err != nil {
				return err
			}
			defer closer()
			rows, err := db.QueryContext(ctx, `SELECT name, gql, COALESCE(sort,''), COALESCE(mode,''), updated_at FROM search_presets ORDER BY name`)
			if err != nil {
				return err
			}
			defer rows.Close()
			n := 0
			for rows.Next() {
				var name, gql, sort, mode, updated string
				if err := rows.Scan(&name, &gql, &sort, &mode, &updated); err != nil {
					return err
				}
				printf(out, "  %-24s %s", name, gql)
				if sort != "" {
					printf(out, "  --sort %s", sort)
				}
				if mode != "" {
					printf(out, "  --mode %s", mode)
				}
				printf(out, "\n")
				n++
			}
			if err := rows.Err(); err != nil {
				return err
			}
			if n == 0 {
				printf(out, "No presets saved. Try: gseer preset add my-query 'port == 443'\n")
			}
			return nil
		},
	}
}

func presetRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <name>",
		Short: "Delete a saved preset",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := commandContext(cmd)
			db, closer, err := openPresetDB(ctx, cmd)
			if err != nil {
				return err
			}
			defer closer()
			res, err := db.ExecContext(ctx, `DELETE FROM search_presets WHERE name = ?`, args[0])
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				printf(out, "no preset named %q\n", args[0])
				return nil
			}
			printf(out, "[ ok  ] preset %q deleted\n", args[0])
			return nil
		},
	}
}
