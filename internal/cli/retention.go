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

// retention.go — `gseer db retention` (R64 storage & retention engine):
// configurable pruning of RAW observations older than a policy age.
//
// Design rules (R64):
//   - DRY-RUN by default: nothing is deleted until --apply is passed.
//   - Only raw observation rows are pruned — assets, services, the
//     maintained latest_* projections and asset_changes events are never
//     touched, so the searchable current state and the change history
//     survive retention.
//   - The floor is 7 days (a lower --older-than is refused) to protect
//     against accidental mass deletion.
//   - A backup reminder is printed (gseer db backup is the owner's tool).

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

func newDBRetentionCmd() *cobra.Command {
	var (
		fOlderThan string
		fApply     bool
	)
	cmd := &cobra.Command{
		Use:   "retention --older-than <duration>",
		Short: "Prune raw observations older than a policy age (DRY-RUN by default; --apply to delete)",
		Long: `Apply a retention policy to raw observations (R64).

Only RAW observation rows older than the cutoff are deleted; assets,
services, the latest_* projections (the searchable current state) and
asset_change events are never touched — evidence summaries survive even
after their raw rows are pruned.

DRY-RUN is the default: run without --apply to see what WOULD be deleted.
A backup first is strongly recommended:
  gseer db backup --out backup.db

Example:
  gseer db retention --older-than 90d            # show what would go
  gseer db retention --older-than 90d --apply    # actually prune`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			days, err := parseRetentionDays(fOlderThan)
			if err != nil {
				printf(out, "E_RETENTION_USAGE: %s\nTry: gseer db retention --older-than 90d\n", err.Error())
				exitWith(ExitInvalidInput)
				return nil
			}
			if days < 7 {
				printf(out, "E_RETENTION_FLOOR: --older-than must be at least 7d (refusing %dd)\nWhy: the retention floor protects against accidental mass deletion\n", days)
				exitWith(ExitInvalidInput)
				return nil
			}
			ctx := commandContext(cmd)
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			if cfg.Profile != "personal" {
				printf(out, "E_PROFILE_UNSUPPORTED: gseer db retention runs on the personal (SQLite) store in this release\n")
				exitWith(ExitConfig)
				return nil
			}
			res, oerr := sqlite.Open(cfg.Database.DSN)
			if oerr != nil {
				return oerr
			}
			defer func() { _ = res.DB.Close() }()

			cutoff := time.Now().UTC().AddDate(0, 0, -days)
			cutoffStr := cutoff.Format("2006-01-02T15:04:05.000000Z")
			var n int64
			if err := res.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM observations WHERE observed_at < ?`, cutoffStr).Scan(&n); err != nil {
				return err
			}
			if !fApply {
				printf(out, "DRY-RUN: %d raw observation(s) older than %s (%s) would be deleted.\n", n, fOlderThan, cutoffStr)
				printf(out, "Assets, services, latest_* projections and change events are NEVER touched.\n")
				printf(out, "To apply: gseer db retention --older-than %s --apply   (backup first: gseer db backup --out backup.db)\n", fOlderThan)
				return nil
			}
			r, err := res.DB.ExecContext(ctx, `DELETE FROM observations WHERE observed_at < ?`, cutoffStr)
			if err != nil {
				return err
			}
			deleted, _ := r.RowsAffected()
			printf(out, "[ ok  ] retention applied: %d raw observation(s) deleted (older than %s).\n", deleted, cutoffStr)
			printf(out, "        Searchable current state, latest_* projections and change events untouched.\n")
			printf(out, "        Note: run gseer changes detect afterwards? Not needed — detection uses\n")
			printf(out, "        the observation log; pruned rows no longer participate.\n")
			return nil
		},
	}
	cmd.Flags().StringVar(&fOlderThan, "older-than", "", "prune observations older than this duration (e.g. 30d, 90d, 1y; floor 7d)")
	cmd.Flags().BoolVar(&fApply, "apply", false, "actually delete (default is dry-run)")
	return cmd
}

// parseRetentionDays accepts 30d / 6m / 1y / 14 (bare days).
func parseRetentionDays(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, fmt.Errorf("--older-than is required")
	}
	num := s
	unit := "d"
	if strings.HasSuffix(s, "d") || strings.HasSuffix(s, "m") || strings.HasSuffix(s, "y") {
		unit = s[len(s)-1:]
		num = s[:len(s)-1]
	}
	n, err := strconv.Atoi(num)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("cannot parse duration %q", s)
	}
	switch unit {
	case "d":
		return n, nil
	case "m":
		return n * 30, nil
	case "y":
		return n * 365, nil
	}
	return 0, fmt.Errorf("unknown duration %q", s)
}
