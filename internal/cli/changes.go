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

// changes.go — `gseer changes` (R57): run change detection over the
// observation log and list the searchable change events.  Detection is
// evidence-based (internal/changes): events only when a projected value
// actually differs from the previous observation — routine refreshes of
// unchanged data emit nothing, and every event carries the provenance of
// the observation that revealed it.  Search never triggers detection
// (read-only separation, ADR-0010).

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/changes"
)

// registerChangesCmd attaches `gseer changes detect|list`.
func registerChangesCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "changes",
		Short: "Detect and search asset changes over the observation log (evidence-based)",
		Long: `Detect and list changes between observations (R56/R57).

` + "`gseer changes detect`" + ` walks the observation log (the historical
evidence GSEER already stores) and records an event when a projected value
actually differs from the previous observation: DNS record, ASN/prefix
attribution, certificate, TLS version, HTTP status/title/server, service
technologies, banner, plus first sightings.  Routine refreshes of unchanged
data emit NOTHING.  Every event carries the source and the observed_at of
the observation that revealed it — no invented history.

Detection is incremental (checkpointed) and idempotent: re-running it can
never duplicate events, and a corrupt checkpoint degrades to a safe full
re-detect.` + "\n\nExamples:\n" + `
  gseer changes detect               # incremental (checkpointed)
  gseer changes detect --full        # full re-detect (idempotent)
  gseer changes list --kind tls.cert --limit 50
  gseer changes list --asset 203.0.113.7 --format json`,
	}
	cmd.AddCommand(changesDetectCmd(), changesListCmd())
	root.AddCommand(cmd)
}

func changesDetectCmd() *cobra.Command {
	var fFull bool
	cmd := &cobra.Command{
		Use:   "detect",
		Short: "Derive change events from the observation log (incremental, idempotent)",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			ctx := commandContext(cmd)
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			store, _, err := personalStore(ctx, cfg)
			if err != nil {
				return err
			}
			defer func() { _ = store.DB.Close() }()
			st, err := changes.Detect(ctx, store.DB, fFull)
			if err != nil {
				return err
			}
			printf(out, "[ ok  ] change detection complete (%s)\n", modeLabel(st.FullRescan))
			printf(out, "        observations scanned: %d · assets scanned: %d\n", st.ObservationsScanned, st.AssetsScanned)
			printf(out, "        events recorded: %d (deduped: %d) · took %d ms\n",
				st.EventsEmitted, st.EventsDeduped, st.DurationMs)
			printf(out, "        checkpoint: last observation id %d\n", st.LastObsID)
			return nil
		},
	}
	cmd.Flags().BoolVar(&fFull, "full", false, "re-detect all assets (idempotent; events are never duplicated)")
	return cmd
}

func modeLabel(full bool) string {
	if full {
		return "full rescan"
	}
	return "incremental"
}

type changeRow struct {
	ID         int64  `json:"id"`
	AssetValue string `json:"asset_value"`
	AssetKind  string `json:"asset_kind"`
	ServiceID  int64  `json:"service_id"`
	Kind       string `json:"change_kind"`
	OldValue   string `json:"old_value"`
	NewValue   string `json:"new_value"`
	ObservedAt string `json:"observed_at"`
	DetectedAt string `json:"detected_at"`
	Provenance string `json:"provenance"`
	Source     string `json:"source"`
}

func changesListCmd() *cobra.Command {
	var (
		fKind   string
		fAsset  string
		fLimit  int
		fSince  string
		fFormat string
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List recorded change events (searchable, provenance-bearing)",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if fFormat != "" {
				switch fFormat {
				case "table", "json", "csv", "ndjson":
					flags.output = fFormat
				default:
					printf(out, "E_CHANGES_FORMAT: unknown --format %q\nWhy: list supports table|json|csv|ndjson\n", fFormat)
					exitWith(ExitInvalidInput)
				}
			}
			ctx := commandContext(cmd)
			cfg, cerr := engineConfigOrInit(cmd)
			if cerr != nil {
				return cerr
			}
			store, _, err := personalStore(ctx, cfg)
			if err != nil {
				return err
			}
			defer func() { _ = store.DB.Close() }()

			where := []string{"1=1"}
			var qargs []any
			if fKind != "" {
				where = append(where, "c.change_kind = ?")
				qargs = append(qargs, fKind)
			}
			if fAsset != "" {
				where = append(where, "a.value = ?")
				qargs = append(qargs, fAsset)
			}
			if fSince != "" {
				where = append(where, "c.observed_at >= ?")
				qargs = append(qargs, fSince)
			}
			if fLimit <= 0 {
				fLimit = 50
			}
			qargs = append(qargs, fLimit)
			query := `SELECT c.id, COALESCE(a.value, ''), COALESCE(a.kind, ''),
				COALESCE(c.service_id, 0), c.change_kind, COALESCE(c.old_value, ''),
				c.new_value, c.observed_at, c.detected_at, c.provenance,
				COALESCE(ds.name, '')
				FROM asset_changes c
				JOIN assets a ON a.id = c.asset_id
				LEFT JOIN data_sources ds ON ds.id = c.source_id
				WHERE ` + strings.Join(where, " AND ") + `
				ORDER BY c.observed_at DESC, c.id DESC
				LIMIT ?`
			rows, err := store.DB.QueryContext(ctx, query, qargs...)
			if err != nil {
				return err
			}
			defer rows.Close()
			var outRows []changeRow
			for rows.Next() {
				var r changeRow
				if err := rows.Scan(&r.ID, &r.AssetValue, &r.AssetKind, &r.ServiceID,
					&r.Kind, &r.OldValue, &r.NewValue, &r.ObservedAt, &r.DetectedAt,
					&r.Provenance, &r.Source); err != nil {
					return err
				}
				outRows = append(outRows, r)
			}
			if err := rows.Err(); err != nil {
				return err
			}
			switch outputMode() {
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(map[string]any{"count": len(outRows), "changes": outRows})
			case "csv", "ndjson":
				w := csv.NewWriter(out)
				defer w.Flush()
				_ = w.Write([]string{"observed_at", "change_kind", "asset_value", "asset_kind", "old_value", "new_value", "source", "provenance"})
				for _, r := range outRows {
					if outputMode() == "ndjson" {
						enc := json.NewEncoder(out)
						_ = enc.Encode(r)
						continue
					}
					_ = w.Write([]string{r.ObservedAt, r.Kind, r.AssetValue, r.AssetKind, r.OldValue, r.NewValue, r.Source, r.Provenance})
				}
				return nil
			}
			if len(outRows) == 0 {
				printf(out, "No change events recorded. Try: gseer changes detect\n")
				return nil
			}
			printf(out, "%d change event(s) (newest first):\n", len(outRows))
			for _, r := range outRows {
				svc := ""
				if r.ServiceID != 0 {
					svc = fmt.Sprintf(" svc#%d", r.ServiceID)
				}
				printf(out, "  %s  %-12s %-24s %s → %s  (%s%s)\n",
					r.ObservedAt, r.Kind, r.AssetValue, r.OldValue, r.NewValue, r.Source, svc)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&fKind, "kind", "", "filter by change kind (asset.new, service.new, dns.record, asn.prefix, ct.cert, http.status, http.title, http.server, tls.version, tls.cert, tech, banner)")
	cmd.Flags().StringVar(&fAsset, "asset", "", "filter by asset value (exact)")
	cmd.Flags().StringVar(&fSince, "since", "", "only events observed at/after this RFC3339 time")
	cmd.Flags().IntVar(&fLimit, "limit", 50, "maximum events to list")
	cmd.Flags().StringVar(&fFormat, "format", "", "output format: table|json|csv|ndjson")
	return cmd
}

// hostHistory renders the observation timeline + change events for one
// asset (R56 historical query capability).  Everything shown comes from
// stored observations/events — inferred history is labeled as such.
func hostHistory(ctx context.Context, db *sql.DB, identifier string, out io.Writer) error {
	var assetID int64
	if err := db.QueryRowContext(ctx, `SELECT id FROM assets WHERE value = ?`, identifier).Scan(&assetID); err != nil {
		return fmt.Errorf("no asset %q in the local index", identifier)
	}
	rows, err := db.QueryContext(ctx, `
		SELECT o.observed_at, o.provenance, COALESCE(ds.name, ''), COALESCE(o.service_id, 0), o.evidence
		FROM observations o
		LEFT JOIN data_sources ds ON ds.id = o.source_id
		WHERE o.asset_id = ?
		ORDER BY o.observed_at DESC, o.id DESC
		LIMIT 200`, assetID)
	if err != nil {
		return err
	}
	defer rows.Close()
	printf(out, "\nObservation timeline (newest first, up to 200):\n")
	n := 0
	for rows.Next() {
		var (
			observedAt, prov, source string
			svcID                    int64
			evidenceRaw              string
		)
		if err := rows.Scan(&observedAt, &prov, &source, &svcID, &evidenceRaw); err != nil {
			return err
		}
		families := evidenceFamilies(evidenceRaw)
		svc := ""
		if svcID != 0 {
			svc = fmt.Sprintf(" svc#%d", svcID)
		}
		printf(out, "  %s  %s  %-14s %s%s\n", observedAt, prov, source, families, svc)
		n++
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if n == 0 {
		printf(out, "  (no observations)\n")
	}

	crows, err := db.QueryContext(ctx, `
		SELECT change_kind, COALESCE(old_value, ''), new_value, observed_at, provenance
		FROM asset_changes WHERE asset_id = ?
		ORDER BY observed_at DESC, id DESC
		LIMIT 100`, assetID)
	if err != nil {
		return err
	}
	defer crows.Close()
	printf(out, "\nDetected changes (newest first, up to 100):\n")
	m := 0
	for crows.Next() {
		var kind, oldV, newV, observedAt, prov string
		if err := crows.Scan(&kind, &oldV, &newV, &observedAt, &prov); err != nil {
			return err
		}
		printf(out, "  %s  %-12s %s → %s  (%s)\n", observedAt, kind, oldV, newV, prov)
		m++
	}
	if err := crows.Err(); err != nil {
		return err
	}
	if m == 0 {
		printf(out, "  (none recorded — try: gseer changes detect)\n")
	}
	return nil
}

// evidenceFamilies summarizes which evidence families one observation
// carries (compact single-token summary for the timeline view).
func evidenceFamilies(evidenceRaw string) string {
	var doc map[string]any
	if err := json.Unmarshal([]byte(evidenceRaw), &doc); err != nil {
		return "(unparseable)"
	}
	fams := make([]string, 0, len(doc))
	for _, k := range []string{"dns", "ip2asn", "ctlog", "http", "tls", "fingerprint", "ssh"} {
		if _, ok := doc[k]; ok {
			fams = append(fams, k)
		}
	}
	if len(fams) == 0 {
		return "(none)"
	}
	return strings.Join(fams, "+")
}
