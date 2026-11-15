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

// setup_index.go — the v0.3.2 setup surfaces that fix the audited
// failures (STAGE 4 scope item 4) and deliver the approved Easy-to-Use
// default (MASTER PROMPT §3):
//
//   - `gseer setup` on a fresh machine provisions PERSONAL MODE and
//     downloads the official SIGNED shared index — no seeds, no
//     endpoint knowledge, no database configuration;
//   - `gseer setup --server <url>` persists client.endpoint (the M11
//     wizard the old print-only branch advertised but never had) and
//     health-checks the endpoint;
//   - configuration failures exit 3 (ExitConfig) instead of the raw
//     exit-1 path;
//   - an existing personal config gets an idempotent store check plus
//     a best-effort index refresh instead of the mislabeled
//     "client profile: no endpoint configured yet." tail.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/index"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// renderConfigError prints a config-layer error per the style guide and
// exits with ExitConfig (3) — the SPEC-03 §9 code for configuration
// failure (v0.3.2 fix: setup used to return the raw error and exit 1).
func renderConfigError(cmd *cobra.Command, err error) {
	printf(cmd.ErrOrStderr(), "%v\n", err)
	exitWith(ExitConfig)
}

// runSetupSharedIndexDefault is the fresh-machine default: provision
// personal mode (offline-safe), then fetch the official shared index
// (network best-effort; trust failures are fatal).  This is the
// MASTER §3 experience: install → setup → search, with no manual
// endpoint discovery, seed entry, or database configuration.
func runSetupSharedIndexDefault(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	printf(out, "Fresh install — configuring PERSONAL MODE + the official SHARED INDEX.\n\n")
	if err := runSetupPersonal(cmd, "", false); err != nil {
		return err
	}
	cfg, cerr := config.Load(config.Flags{
		ConfigPath: flags.configPath,
		Profile:    flags.profile,
		Endpoint:   flags.server,
	})
	if cerr != nil {
		renderConfigError(cmd, cerr)
		return nil
	}
	store, res, err := personalStore(commandContext(cmd), cfg)
	if err != nil {
		return fmt.Errorf("E_SETUP_DB: cannot open the personal database: %w\n"+
			"Try: gseer setup --personal  (provisions the database file)", err)
	}
	defer func() { _ = res.DB.Close() }()
	refreshSharedIndex(cmd, store, cfg, true)
	printf(out, "\nNext:\n")
	printf(out, "  gseer search 'nginx'            — query the shared index\n")
	printf(out, "  gseer index status              — what is installed and how fresh\n")
	printf(out, "  gseer doctor                    — verify the environment\n")
	return nil
}

// runSetupPersonalRefresh is the `gseer setup` tail for an EXISTING
// personal config: idempotent store check + best-effort index refresh
// (replaces the old mislabeled print-only client tail).
func runSetupPersonalRefresh(cmd *cobra.Command, cfg *config.Config) error {
	out := cmd.OutOrStdout()
	store, res, err := personalStore(commandContext(cmd), cfg)
	if err != nil {
		return fmt.Errorf("E_SETUP_DB: cannot open the personal database: %w\n"+
			"Try: gseer setup --personal  (provisions the database file)", err)
	}
	defer func() { _ = res.DB.Close() }()
	printf(out, "[ ok  ] personal database: %s (migrations idempotent at head)\n", res.Path)
	refreshSharedIndex(cmd, store, cfg, false)
	printf(out, "\nNext:\n")
	printf(out, "  gseer search 'port==443'        — query the index (personal mode)\n")
	printf(out, "  gseer index status              — shared-index freshness\n")
	return nil
}

// refreshSharedIndex runs the full shared-index trust chain against
// the personal store.  Network/availability failures are WARN +
// continue (the engine works offline; a retry is one command) — EXCEPT
// trust failures (unsigned/bad signature), which are fatal exit 5: an
// untrusted index is never applied, silently skipped, or downgraded to
// a warning.
func refreshSharedIndex(cmd *cobra.Command, store *sqlite.Store, cfg *config.Config, freshInstall bool) {
	out := cmd.OutOrStdout()
	url := cfg.Index.ManifestURL
	if url == "" {
		url = config.OfficialIndexManifestURL
	}
	printf(out, "[ ..  ] shared index: %s\n", url)
	r, err := index.Update(commandContext(cmd), index.Options{
		ManifestURL: url,
		Dir:         sharedIndexDir(),
		Store:       store,
	})
	if err != nil {
		msg := err.Error()
		if strings.Contains(msg, "E_INDEX_UNSIGNED") || strings.Contains(msg, "E_INDEX_BAD_SIGNATURE") {
			printf(cmd.ErrOrStderr(), "%v\n", err)
			exitWith(ExitAuth) // trust failure: refuse, never warn-and-continue
		}
		if freshInstall {
			printf(out, "[warn] shared index not fetched: %v\n", err)
			printf(out, "       the engine works offline; fetch later with: gseer index update\n")
		} else {
			printf(out, "[warn] shared index refresh failed: %v\n", err)
			printf(out, "       retry later with: gseer index update\n")
		}
		return
	}
	if r.UpToDate && !r.Installed {
		printf(out, "[ ok  ] shared index: already at sequence %d (built %s)\n", r.LocalSeq, fmtTime(r.Remote.BuiltAt))
		if r.ImportResult != nil {
			renderImport(out, r.ImportResult)
		}
		return
	}
	printf(out, "[ ok  ] shared index: verified + installed sequence %d (built %s, schema v%d)\n",
		r.RemoteSeq, fmtTime(r.Remote.BuiltAt), r.Remote.SchemaVersion)
	if r.ImportResult != nil {
		renderImport(out, r.ImportResult)
	}
}

// runSetupClientWizard implements `gseer setup --server <url>`: persist
// client.endpoint to the config file (the wizard the old print-only
// branch advertised), then health-check the endpoint.
func runSetupClientWizard(cmd *cobra.Command, cfg *config.Config) error {
	out := cmd.OutOrStdout()
	endpoint := strings.TrimRight(cfg.Client.Endpoint, "/")
	if endpoint == "" {
		return fmt.Errorf("E_SETUP_USAGE: --server needs an endpoint URL\n" +
			"Try: gseer setup --server https://gseer.example.com")
	}
	cfgPath := flags.configPath
	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	if err := writeClientConfig(cfgPath, endpoint); err != nil {
		return err
	}
	printf(out, "[ ok  ] config written: %s (profile=client, endpoint=%s)\n", cfgPath, endpoint)
	verifyClientEndpoint(cmd, endpoint)
	printf(out, "\nNext:\n")
	printf(out, "  gseer search 'nginx'            — query the endpoint (read-only REST)\n")
	return nil
}

// runSetupClientStatus is the `gseer setup` tail for an EXISTING
// client config: report + health-check (replaces the mislabeled
// "no endpoint configured yet." print-only tail).
func runSetupClientStatus(cmd *cobra.Command, cfg *config.Config) error {
	out := cmd.OutOrStdout()
	endpoint := strings.TrimRight(cfg.Client.Endpoint, "/")
	printf(out, "[ ok  ] client profile: endpoint %s\n", endpoint)
	verifyClientEndpoint(cmd, endpoint)
	printf(out, "\nNext:\n")
	printf(out, "  gseer search 'port==443'        — query the endpoint\n")
	printf(out, "  gseer doctor                    — verify the environment\n")
	return nil
}

// verifyClientEndpoint health-checks the configured endpoint
// (GET /api/v1/health).  An unreachable endpoint exits 4 (SPEC-03 §9:
// service unavailable) — the config IS persisted, so fixing the network
// or the endpoint URL is the only remaining step.
func verifyClientEndpoint(cmd *cobra.Command, endpoint string) {
	out := cmd.OutOrStdout()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(endpoint + "/api/v1/health")
	if err != nil {
		printf(out, "[FAIL] endpoint health check: %v\n", err)
		printf(out, "       the config is saved; re-run `gseer setup` when the endpoint answers\n")
		exitWith(ExitUnavailable)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		printf(out, "[FAIL] endpoint health check: HTTP %d from %s/api/v1/health\n", resp.StatusCode, endpoint)
		exitWith(ExitUnavailable)
		return
	}
	printf(out, "[ ok  ] endpoint healthy: %s\n", endpoint)
}

// writeClientConfig writes the minimal client config (hand-rolled YAML
// so no unused sections are serialized — mirrors writePersonalConfig).
func writeClientConfig(path, endpoint string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("cannot create the config directory: %w", err)
	}
	body := fmt.Sprintf(`# GSEER client mode — queries the configured endpoint's REST API.
# Provisioned by: gseer setup --server <url>
profile: client

client:
  endpoint: %s
`, yamlQuote(endpoint))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return fmt.Errorf("cannot write the config: %w", err)
	}
	return nil
}
