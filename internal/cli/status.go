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

// status.go — `gseer status`: ONE informational view of the product
// state (binary, profile/config, database, shared index).  Doctor
// remains the PASS/FAIL surface; status is informational and always
// exits 0, reporting honest "not provisioned"/"not installed" states
// instead of guessing.  Output: table (default) or -o json|yaml.
package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/index"
	"github.com/Lutfifakee-Project/gseer/internal/version"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// statusView is the render model for `gseer status`.  Pointer-ish
// fields are nil when the state is honestly absent (no config, no
// database, no shared index installed).
type statusView struct {
	Binary      statusBinary     `json:"binary"`
	Profile     statusProfile    `json:"profile"`
	Database    *statusDatabase  `json:"database"`
	SharedIndex *statusSharedIdx `json:"shared_index"`
}

type statusBinary struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
	SHA256  string `json:"sha256"`
}

type statusProfile struct {
	Name       string `json:"name"`
	ConfigPath string `json:"config_path,omitempty"`
	NotedAs    string `json:"noted_as,omitempty"`
}

type statusDatabase struct {
	Path      string `json:"path"`
	SizeBytes int64  `json:"size_bytes"`
}

type statusSharedIdx struct {
	Sequence    int64  `json:"sequence"`
	BuiltAt     string `json:"built_at"`
	ArtifactSHA string `json:"artifact_sha256"`
	Channel     string `json:"channel"`
	Imported    bool   `json:"imported"`
}

func registerStatusCmd(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "One informational view of the product state (binary, profile, database, shared index)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			view := collectStatusView()

			switch format := flags.output; format {
			case "", "table":
				renderStatusTable(out, view)
			case "json":
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(view); err != nil {
					return err
				}
			case "yaml":
				enc := yaml.NewEncoder(out)
				if err := enc.Encode(view); err != nil {
					return err
				}
				_ = enc.Close()
			default:
				printf(cmd.ErrOrStderr(), "E_STATUS_OUTPUT: unsupported output format %q (table|json|yaml)\n", format)
				exitWith(ExitInvalidInput) // SPEC-03 §9: invalid input = 2
				return nil
			}
			return nil
		},
	}
	root.AddCommand(cmd)
}

// collectStatusView gathers every section independently; a failure in
// one section degrades to an honest "not provisioned/not installed"
// state, never an error.
func collectStatusView() statusView {
	v := statusView{}

	info := version.Current()
	v.Binary = statusBinary{
		Version: orUnknownStr(info.Version),
		Commit:  orUnknownStr(info.Commit),
		BuiltAt: orUnknownStr(info.BuiltAt),
		SHA256:  orUnknownStr(binarySHA256()),
	}

	// Profile/config: the config file may legitimately not exist yet
	// (fresh machine before the first `gseer` run).
	cfgPath := flags.configPath
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if _, err := os.Stat(cfgPath); err != nil {
		v.Profile = statusProfile{Name: "not provisioned", NotedAs: "no config yet — run: gseer setup"}
	} else {
		cfg, err := config.Load(config.Flags{
			ConfigPath: flags.configPath,
			Profile:    flags.profile,
			Endpoint:   flags.server,
		})
		if err != nil {
			v.Profile = statusProfile{Name: "invalid config", ConfigPath: cfgPath, NotedAs: "gseer doctor explains the exact failure"}
		} else {
			v.Profile = statusProfile{Name: string(cfg.Profile), ConfigPath: cfgPath}
		}
	}

	// Database (personal mode): the file may legitimately not exist yet.
	dbPath := ""
	if _, err := os.Stat(cfgPath); err == nil {
		if cfg, err := config.Load(config.Flags{
			ConfigPath: flags.configPath,
			Profile:    flags.profile,
			Endpoint:   flags.server,
		}); err == nil && cfg.Profile == config.ProfilePersonal {
			dbPath = cfg.Database.DSN
		}
	}
	if dbPath == "" {
		dbPath = defaultPersonalDBPath()
	}
	if st, err := os.Stat(dbPath); err == nil {
		v.Database = &statusDatabase{Path: dbPath, SizeBytes: st.Size()}
	} else {
		v.Database = &statusDatabase{Path: dbPath, SizeBytes: -1} // -1 = not provisioned
	}

	// Shared index: installed state is honest about absence.
	st, err := index.LoadState(sharedIndexDir())
	if err == nil && st != nil {
		v.SharedIndex = &statusSharedIdx{
			Sequence:    st.Sequence,
			BuiltAt:     fmtTime(st.BuiltAt),
			ArtifactSHA: st.ArtifactSHA,
			Channel:     st.ManifestURL,
			Imported:    st.Imported,
		}
	}
	return v
}

func renderStatusTable(out interface{ Write([]byte) (int, error) }, v statusView) {
	printf(out, "GSEER status\n")
	printf(out, "  binary       : gseer v%s (commit %s, built %s) sha256=%s\n",
		v.Binary.Version, v.Binary.Commit, v.Binary.BuiltAt, v.Binary.SHA256)
	if v.Profile.NotedAs != "" {
		printf(out, "  profile      : %s (%s)\n", v.Profile.Name, v.Profile.NotedAs)
	} else {
		printf(out, "  profile      : %s (config: %s)\n", v.Profile.Name, v.Profile.ConfigPath)
	}
	switch {
	case v.Database == nil:
		printf(out, "  database     : unknown\n")
	case v.Database.SizeBytes < 0:
		printf(out, "  database     : not provisioned (%s)\n", v.Database.Path)
	default:
		printf(out, "  database     : %s (%d bytes)\n", v.Database.Path, v.Database.SizeBytes)
	}
	if v.SharedIndex == nil {
		printf(out, "  shared index : not installed — Try: gseer setup  (personal mode + shared index) or gseer index update\n")
	} else {
		age := ""
		if t, err := time.Parse(time.RFC3339, v.SharedIndex.BuiltAt); err == nil && !t.IsZero() {
			age = fmt.Sprintf(", age %s", time.Since(t).Round(time.Second))
		}
		printf(out, "  shared index : verified + installed sequence %d (built %s%s)\n",
			v.SharedIndex.Sequence, v.SharedIndex.BuiltAt, age)
		printf(out, "                 channel %s, imported into store: %v\n", v.SharedIndex.Channel, v.SharedIndex.Imported)
		if !v.SharedIndex.Imported {
			printf(out, "                 Try: gseer index update  (re-runs the import; idempotent)\n")
		}
	}
}

// orUnknownStr keeps the informational view honest when build metadata
// is absent (go install builds carry no VCS metadata).
func orUnknownStr(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
