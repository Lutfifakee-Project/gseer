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

// setup_bootstrap.go — the local passive-discovery bootstrap (v0.3.2
// CLI-only architecture; owner directive §6).
//
// With the shared-index channel REMOVED, a fresh install gets real
// internet-asset data through LOCAL discovery only.  `gseer setup`
// therefore bootstraps discovery from the operator's own egress
// context — no manual seed input, no database server, no collector
// command, no GitHub Actions configuration:
//
//  1. CONTEXT   — detect the egress IP (public HTTPS echo, provenance
//     recorded) and its reverse-DNS hostname; derive the registrable
//     domain (publicsuffix).  Offline or inconclusive ⇒ an honest
//     "[skip]" and a manual pointer; setup never fabricates facts.
//  2. PASSIVE   — register the `bootstrap-*` sources (ptr, dns, ip2asn —
//     the connectors whose terms review is ENABLED; ct and rdap stay
//     disabled by the SOURCES.md register) and run one bounded collect
//     pass through the SAME runner/ingest path every other writer uses.
//  3. OBSERVE   — at most 3 TLS :443 handshakes against web-class
//     hostnames of the derived domain, under an auto-created, audited,
//     revocable scope (domain_suffix, tls/443, 1 request per run) — the
//     honesty contract reserves PORT facts to explicit observation
//     (collect/doc.go contract 3), so this bounded stage is what lets
//     `gseer search "port=443"` return real, verifiable evidence right
//     after setup.  Search itself never triggers discovery.
//
// Every stage is idempotent: re-running `gseer setup` upserts the
// sources (L1/L2 delivery-identity dedupe) and refreshes evidence.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/collect"
	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/dataset"
	"github.com/Lutfifakee-Project/gseer/internal/observe"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"

	"golang.org/x/net/publicsuffix"
)

// Bootstrap bounds — small on purpose: setup is a bootstrap, not a
// harvest, and every network touch is a public protocol lookup.
const (
	bootstrapContextTimeout = 15 * time.Second
	bootstrapCollectTimeout = 90 * time.Second
	bootstrapObserveTimeout = 8 * time.Second
	bootstrapDatasetTimeout = 120 * time.Second
	bootstrapMaxTargets     = 3
	bootstrapEgressEcho     = "https://api.ipify.org"
	bootstrapSourcePrefix   = "bootstrap-"
)

// runSetupBootstrapDefault implements the fresh-machine `gseer setup`:
// provision personal mode, bootstrap local passive discovery, then
// import the central dataset (Rev 9 — the owner-mandated central
// distribution; the journey's reliable data path).
func runSetupBootstrapDefault(cmd *cobra.Command) error {
	if err := runSetupPersonal(cmd, "", false); err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	printf(out, "\n")
	if err := bootstrapDiscovery(cmd, false); err != nil {
		return err
	}
	runDatasetAutoImport(cmd, out)
	return nil
}

// runSetupPersonalRefresh is the configured-personal tail of a setup
// invocation: re-run the idempotent bootstrap (sources are upserted;
// facts dedupe at the delivery identity), then refresh the dataset.
func runSetupPersonalRefresh(cmd *cobra.Command, cfg *config.Config) error {
	out := cmd.OutOrStdout()
	printf(out, "[ ok  ] personal config loaded: %s (profile=personal)\n", cfg.Source)
	if err := bootstrapDiscovery(cmd, true); err != nil {
		return err
	}
	runDatasetAutoImport(cmd, out)
	return nil
}

// runDatasetAutoImport imports the latest central dataset into the
// Local Index (setup's Stage 4 — owner directive: the user never
// collects the dataset or runs Actions manually).  Connection failure
// is SAFE and HONEST: a [warn] line, the engine keeps working with
// whatever local discovery produced, and setup still exits 0 — nothing
// is half-imported (the import itself is atomic with rollback).
func runDatasetAutoImport(cmd *cobra.Command, out interface{ Write([]byte) (int, error) }) {
	cfg, cfgErr := config.Load(config.Flags{
		ConfigPath: flags.configPath,
		Profile:    flags.profile,
	})
	if cfgErr != nil || cfg.Profile != config.ProfilePersonal {
		return // the bootstrap section already reported any config problem
	}
	channel := resolveManifestURL(cfg, "")
	fetcher := dataset.NewFetcher()
	ctx, cancel := context.WithTimeout(commandContext(cmd), bootstrapDatasetTimeout)
	defer cancel()

	printf(out, "[ ..  ] dataset: importing the central dataset (%s)\n", channel)
	manifest, err := fetcher.FetchManifest(ctx, channel)
	if err != nil {
		printf(out, "[warn ] dataset: %v\n", err)
		printf(out, "        manual retry: gseer dataset update   (setup continues — local discovery still works)\n")
		return
	}
	state, serr := loadDatasetState(cmd, cfg)
	if serr == nil && state.Installed && manifest.DatasetVersion <= state.DatasetVersion {
		printf(out, "[ ok  ] dataset: already at version %d (freshness %s)\n",
			state.DatasetVersion, orNeverTime(&state.NewestObservedAt))
		return
	}
	payloadPath, err := fetcher.FetchPayload(ctx, channel, manifest)
	if err != nil {
		printf(out, "[warn ] dataset: %v\n", err)
		printf(out, "        manual retry: gseer dataset update\n")
		return
	}
	defer func() { _ = removeFile(payloadPath) }()
	result, err := dataset.Import(ctx, dataset.ImportOptions{
		DBPath:      cfg.Database.DSN,
		PayloadPath: payloadPath,
		Manifest:    manifest,
		ManifestURL: channel,
	})
	if err != nil {
		printf(out, "[warn ] dataset: %v\n", err)
		printf(out, "        manual retry: gseer dataset update\n")
		return
	}
	if result.Recovered {
		printf(out, "[ ok  ] dataset: recovered an interrupted import before this one\n")
	}
	printf(out, "[ ok  ] dataset v%d imported: %d observations ingested, %d deduped, %d suppressed by YOUR rules\n",
		manifest.DatasetVersion, result.Stats.ObservationsInserted, result.Stats.ObservationsDeduped, result.Stats.Suppressed)
	printDatasetFreshness(out, manifest, nil)
}

// runSetupPersonalFlagDefault is not used directly; --personal keeps
// its existing contract (runSetupPersonalFlag → runSetupPersonal).

// renderConfigError prints a config-layer error per the style guide and
// exits with ExitConfig (3) — the SPEC-03 §9 code for configuration
// failure (v0.3.2 fix: setup used to return the raw error and exit 1).
func renderConfigError(cmd *cobra.Command, err error) {
	printf(cmd.ErrOrStderr(), "%v\n", err)
	exitWith(ExitConfig)
}

// bootstrapDiscovery runs the three bootstrap stages.  refresh toggles
// the wording (first bootstrap vs. idempotent re-run).
func bootstrapDiscovery(cmd *cobra.Command, refresh bool) error {
	out := cmd.OutOrStdout()
	cfg, cfgErr := config.Load(config.Flags{
		ConfigPath: flags.configPath,
		Profile:    flags.profile,
	})
	if cfgErr != nil {
		return fmt.Errorf("E_CONFIG: %s", cfgErr.Error())
	}
	if cfg.Profile != config.ProfilePersonal {
		// Defensive: the bootstrap is a personal-mode surface (config
		// validation admits only personal/self-hosted; self-hosted
		// setups reach runSetupSelfHosted instead).
		printf(out, "[skip ] discovery bootstrap: profile %q is not personal\n", cfg.Profile)
		return nil
	}
	res, err := openPersonal(cfg)
	if err != nil {
		return fmt.Errorf("E_DB_UNAVAILABLE: cannot open the personal database: %v", err)
	}
	defer func() { _ = res.DB.Close() }()
	store := sqlite.NewStore(res.DB)

	if refresh {
		printf(out, "[ ..  ] refreshing local discovery bootstrap (idempotent; facts dedupe)\n")
	} else {
		printf(out, "[ ..  ] bootstrapping local passive discovery (no shared index — real data comes from YOUR egress context)\n")
	}

	// Stage 1 — operator egress context.
	ctxCtx, cancel := context.WithTimeout(commandContext(cmd), bootstrapContextTimeout)
	defer cancel()
	egressIP, ptrHost, domain := detectEgressContext(ctxCtx)
	switch {
	case egressIP == "":
		printf(out, "[skip ] context: egress IP undetectable (offline or echo unreachable) — nothing is guessed\n")
		printf(out, "        manual path: gseer source add my-dns --type dns --seeds <domains> --enable --yes\n")
		return nil
	case domain == "":
		printf(out, "[ ok  ] context: egress %s (PTR %q — no registrable domain derivable)\n", egressIP, orNone(ptrHost))
	default:
		printf(out, "[ ok  ] context: egress %s (PTR %q → domain %s)\n", egressIP, orNone(ptrHost), domain)
	}

	// Stage 2 — passive collect pass over the terms-approved connectors.
	ctxCollect, cancel := context.WithTimeout(commandContext(cmd), bootstrapCollectTimeout)
	defer cancel()
	registered := runBootstrapCollectStage(ctxCollect, out, store, egressIP, domain)
	if registered == 0 && egressIP == "" {
		return nil // context stage already reported the honest skip
	}

	// Stage 3 — bounded TLS observation (the only PORT-evidence stage).
	// The honesty contract (collect/doc.go #3) forbids port facts from
	// passive sources; this explicit, scope-gated, ≤3-handshake stage is
	// what makes `gseer search "port=443"` return REAL evidence.
	if domain == "" {
		printf(out, "[skip ] observation: no domain derived — TLS observation is not authorized for arbitrary hosts\n")
		printf(out, "        manual path: gseer scope add ip <your-ip> --protocols tls --ports 443 --yes && gseer scan tls --target <host>\n")
		printBootstrapTail(out, registered)
		return nil
	}
	scopeID, serr := createBootstrapScope(ctxCollect, store, domain)
	if serr != nil {
		printf(out, "[warn ] scope: %v (TLS observation skipped)\n", serr)
		printBootstrapTail(out, registered)
		return nil
	}
	printf(out, "[ ok  ] scope %d: domain_suffix %s, tls/443, max 1 handshake per run (audited; revoke: gseer scope revoke %d)\n",
		scopeID, domain, scopeID)

	gw := &observe.Gateway{Store: store}
	obs := &observe.TLSObserver{GW: gw, Timeout: bootstrapObserveTimeout}
	observed := 0
	for _, target := range bootstrapTargets(domain) {
		res, rerr := obs.Run(ctxCollect, target, 443)
		if rerr != nil {
			if strings.Contains(rerr.Error(), "E_SCOPE_DENIED") {
				printf(out, "[skip ] %s: not authorized (%v)\n", target, rerr)
				continue
			}
			printf(out, "[warn ] %s: %v\n", target, rerr)
			continue
		}
		observed++
		if res.OK {
			printf(out, "[ ok  ] tls %s:443 — %s (ingested=%d deduped=%d provenance=scan-tls)\n",
				target, bootstrapTLSLine(res), res.Ingested, res.Deduped)
		} else {
			printf(out, "[note ] tls %s:443 — %s\n", target, res.Failure)
		}
	}
	printf(out, "[ ok  ] observation: %d host(s) observed under scope %d (search never triggers discovery or scanning)\n",
		observed, scopeID)
	printBootstrapTail(out, registered)
	return nil
}

// runBootstrapCollectStage registers and runs the passive bootstrap
// sources (stage 2).  EnsureSource registers rows enabled=false (the
// operator-registry default); the bootstrap sources are the SETUP's own
// registration, so each is enabled explicitly — they remain visible,
// auditable, and revocable via `gseer source list` / registry edit.
// Returns the number of sources actually registered.
func runBootstrapCollectStage(ctx context.Context, out interface{ Write([]byte) (int, error) }, store *sqlite.Store, egressIP, domain string) int {
	registered := 0
	runSource := func(name, connector, termsRef string, cfgJSON map[string]any) {
		if _, err := store.EnsureSource(ctx, name, connector, termsRef, cfgJSON); err != nil {
			printf(out, "[warn ] source %s: %v\n", name, err)
			return
		}
		if err := store.SetSourceEnabled(ctx, name, true); err != nil {
			printf(out, "[warn ] enable %s: %v\n", name, err)
			return
		}
		registered++
		stats, rerr := collect.NewRunner(store, nil).Run(ctx, name)
		if rerr != nil {
			printf(out, "[warn ] collect %s: %v\n", name, rerr)
			return
		}
		if stats.Skipped != "" {
			printf(out, "[skip ] collect %s: %s\n", name, stats.Skipped)
			return
		}
		printf(out, "[ ok  ] collect %s: %d facts ingested, %d deduped, %d suppressed, %d dead-lettered\n",
			name, stats.Ingested, stats.Deduped, stats.Suppressed, stats.DeadLetter)
	}
	if egressIP != "" {
		runSource(bootstrapSourcePrefix+"ptr", "ptr",
			"docs/SOURCES.md §E (Reverse DNS)",
			map[string]any{"seeds": []string{egressIP}, "seed_mode": "config"})
		runSource(bootstrapSourcePrefix+"asn", "ip2asn",
			"docs/SOURCES.md §D (ASN/BGP IP-to-ASN)",
			map[string]any{"seeds": []string{egressIP}, "seed_mode": "config"})
	}
	if domain != "" {
		runSource(bootstrapSourcePrefix+"dns", "dns",
			"docs/SOURCES.md §C (Public DNS)",
			map[string]any{"seeds": []string{domain}, "seed_mode": "config", "limit_per_run": 20})
	}
	return registered
}

// detectEgressContext returns (egressIP, firstPTRHostname, registrableDomain).
// Every failure is reported as an empty field — the caller prints the
// honest skip; nothing is ever fabricated.
func detectEgressContext(ctx context.Context) (string, string, string) {
	hc := &http.Client{Timeout: 6 * time.Second}
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, bootstrapEgressEcho, nil)
	if rerr != nil {
		return "", "", ""
	}
	resp, err := hc.Do(req)
	if err != nil {
		return "", "", ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", ""
	}
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	ip := strings.TrimSpace(string(buf[:n]))
	if parsed := net.ParseIP(ip); parsed == nil || parsed.IsLoopback() || parsed.IsPrivate() {
		return "", "", ""
	}
	names, lerr := net.LookupAddr(ip)
	if lerr != nil || len(names) == 0 {
		return ip, "", ""
	}
	host := strings.TrimSuffix(names[0], ".")
	domain := ""
	if d, derr := publicsuffix.EffectiveTLDPlusOne(host); derr == nil {
		domain = d
	}
	return ip, host, domain
}

// createBootstrapScope creates the auto-bootstrap allow scope for the
// derived domain: TLS on 443 only, one handshake per run, explicitly
// noted as auto-created and revocable.  The scope AUDIT trail records
// every allow/deny decision (gseer scope audit).
func createBootstrapScope(ctx context.Context, store *sqlite.Store, domain string) (int64, error) {
	sc := &storage.Scope{
		Kind:           storage.ScopeKindDomainSuffix,
		Value:          domain,
		Mode:           "allow",
		Note:           "auto-created by `gseer setup` bootstrap — the operator's own egress context (revoke any time: gseer scope revoke <id>)",
		Protocols:      []string{"tls"},
		Ports:          []int{443},
		MaxConcurrency: 1,
		MaxRequests:    1,
	}
	return store.CreateScope(ctx, sc)
}

// bootstrapTargets names the web-class hostnames to observe: the bare
// domain and its www form (deduplicated, bounded by bootstrapMaxTargets).
func bootstrapTargets(domain string) []string {
	seen := map[string]bool{}
	var out []string
	for _, cand := range []string{"www." + domain, domain} {
		if !seen[cand] {
			seen[cand] = true
			out = append(out, cand)
		}
		if len(out) >= bootstrapMaxTargets {
			break
		}
	}
	return out
}

func bootstrapTLSLine(res *observe.TLSResult) string {
	line := "tls=" + res.TLSVersion + " cipher=" + res.CipherSuite
	if res.SubjectCN != "" {
		line += " subject_cn=" + res.SubjectCN
	}
	if res.IssuerCN != "" {
		line += " issuer=" + res.IssuerCN
	}
	return line
}

func printBootstrapTail(out interface{ Write([]byte) (int, error) }, registered int) {
	printf(out, "\nLocal Index: query it with `gseer search 'port=443'` (search never triggers discovery or scanning).\n")
	if registered > 0 {
		printf(out, "Extend:      gseer source add <name> --type dns --seeds <domains> --enable --yes; gseer collect run\n")
	}
	printf(out, "Freshness:   gseer status | gseer doctor   (per-source registry + last successful run)\n")
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
