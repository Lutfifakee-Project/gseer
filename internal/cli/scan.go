// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// scan.go — `gseer scan` (v0.3.2): the explicit active-observation
// command.  Two SEPARATE observers with separate scopes and separate
// evidence:
//
//	gseer scan http --target <host> --port 80    (HTTP GET; scope protocol "http")
//	gseer scan tls  --target <host> --port 443   (TLS handshake only; scope protocol "tls")
//
// Every connection passes the default-deny gateway (internal/observe):
// no live scope matching the target's address, protocol and port ⇒
// E_SCOPE_DENIED, exit 5, the denial audited, and NO network probe.
// A successful authorization records exactly what the target answered
// (or the honest failure) through the shared ingestion path — a failed
// connection is an observation of failure, never "asset absent".

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/observe"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

func registerScanCmd(root *cobra.Command) {
	scan := &cobra.Command{
		Use:   "scan",
		Short: "Observe ONE explicitly authorized target (gateway-enforced; nothing scans without a scope)",
		Args:  cobra.NoArgs,
		Long: `Observe one target you are authorized to observe.

Active observation is the P2 regime (docs/SCANNING.md): by running a
scan you assert you own or control the target.  Every connection passes
the default-deny gateway:

  - no live scope for the target        -> E_SCOPE_DENIED (exit 5)
  - scope expired / revoked             -> E_SCOPE_DENIED (exit 5)
  - protocol not in the scope           -> E_SCOPE_DENIED (exit 5)
  - port not in the scope               -> E_SCOPE_DENIED (exit 5)
  - private/loopback address unscoped   -> E_SCOPE_DENIED (exit 5)

Every decision — allow AND deny — is audited (gseer scope audit).

Observers are separate: ` + "`scan http`" + ` performs one HTTP GET and records
status/title/server; ` + "`scan tls`" + ` performs one TLS handshake and records
the certificate.  Redirects re-enter the gateway hop by hop; a redirect
to https:// is recorded, not followed (run ` + "`scan tls`" + ` for it).

Observation results land in the SAME index as passive collection, with
their own provenance (scan-http / scan-tls) — GQL search stays
read-only and never scans.

Examples:
  gseer scope add cidr 127.0.0.1/32 --protocols http,tls --ports 8080,8443 --note "my dev server"
  gseer scan http --target localhost --port 8080
  gseer scan tls  --target localhost --port 8443`,
	}
	scan.AddCommand(newScanHTTPCmd(), newScanTLSCmd())
	root.AddCommand(scan)
}

type scanFlags struct {
	target  string
	port    int
	timeout time.Duration
}

func newScanHTTPCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "http",
		Short: "One HTTP GET against a scoped target (records status/title/server)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runScanHTTP(cmd, f) },
	}
	cmd.Flags().StringVar(&f.target, "target", "", "the target host or IP (required)")
	cmd.Flags().IntVar(&f.port, "port", 80, "the target port")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 10*time.Second, "per-hop timeout")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func newScanTLSCmd() *cobra.Command {
	f := &scanFlags{}
	cmd := &cobra.Command{
		Use:   "tls",
		Short: "One TLS handshake against a scoped target (records version + certificate; no HTTP request)",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, args []string) error { return runScanTLS(cmd, f) },
	}
	cmd.Flags().StringVar(&f.target, "target", "", "the target host or IP (required)")
	cmd.Flags().IntVar(&f.port, "port", 443, "the target port")
	cmd.Flags().DurationVar(&f.timeout, "timeout", 10*time.Second, "dial+handshake timeout")
	_ = cmd.MarkFlagRequired("target")
	return cmd
}

func runScanHTTP(cmd *cobra.Command, f *scanFlags) error {
	store, closer, err := openObserveStore(cmd)
	if err != nil {
		return err
	}
	defer closer()
	attachScanFingerprintEngine(cmd, store) // v0.3.2: scan-path enrichment parity (approved STAGE 4 item 5)

	gw := &observe.Gateway{Store: store}
	obs := &observe.HTTPObserver{GW: gw, Timeout: f.timeout}

	res, rerr := obs.Run(commandContext(cmd), f.target, f.port)
	if rerr != nil {
		// Authorization denials are exit 5 (auth failure — the honest
		// code for "you are not allowed to do that").  No probe fired.
		if strings.Contains(rerr.Error(), "E_SCOPE_DENIED") {
			printf(cmd.ErrOrStderr(), "%v\n", rerr)
			exitWith(ExitAuth)
			return nil
		}
		return rerr
	}
	renderScanResult(cmd, res.Protocol, res.Host, res.IP, res.Port, res.OK,
		scanHTTPText(res), res.ScopeID, res.Ingested, res.Deduped)
	return nil
}

func runScanTLS(cmd *cobra.Command, f *scanFlags) error {
	store, closer, err := openObserveStore(cmd)
	if err != nil {
		return err
	}
	defer closer()
	attachScanFingerprintEngine(cmd, store) // v0.3.2: scan-path enrichment parity (approved STAGE 4 item 5)

	gw := &observe.Gateway{Store: store}
	obs := &observe.TLSObserver{GW: gw, Timeout: f.timeout}

	res, rerr := obs.Run(commandContext(cmd), f.target, f.port)
	if rerr != nil {
		if strings.Contains(rerr.Error(), "E_SCOPE_DENIED") {
			printf(cmd.ErrOrStderr(), "%v\n", rerr)
			exitWith(ExitAuth)
			return nil
		}
		return rerr
	}
	renderScanResult(cmd, res.Protocol, res.Host, res.IP, res.Port, res.OK,
		scanTLSText(res), res.ScopeID, res.Ingested, res.Deduped)
	return nil
}

// attachScanFingerprintEngine wires the rule-driven fingerprint engine
// into the scan ingestion path (v0.3.2, approved STAGE 4 item 5).  The
// collect path has attached the engine since v0.1.0 (cli/collect.go);
// the scan observers ingest through the SAME store contract, so without
// this the scan-http/tls evidence was stored un-enriched and the
// rule-derived `technologies` stayed empty for scan data.  Fail-closed
// parity: lint problems disable enrichment for the run with a loud
// warning — exactly the collect-path behavior.
func attachScanFingerprintEngine(cmd *cobra.Command, store observeBackend) {
	cfg, cerr := engineConfigOrInit(cmd)
	if cerr != nil {
		return // the store opened fine; enrichment is optional, never a scan blocker
	}
	if reg, problems := fingerprintEngineFromConfig(cmd, cfg); reg != nil {
		if setter, ok := store.(fingerprintSetter); ok {
			setter.SetFingerprintEngine(reg)
		}
	} else if len(problems) > 0 {
		for _, p := range problems {
			printf(cmd.OutOrStdout(), "[warn] fingerprint rule problem: %s\n", p)
		}
		printf(cmd.OutOrStdout(), "[warn] fingerprint enrichment disabled for this scan (fail-closed)\n")
	}
}

func scanHTTPText(res *observe.ScanResult) string {
	if !res.OK {
		return "result: FAILED — " + res.Failure + "  (recorded as an observation of failure; NOT evidence the asset is absent)"
	}
	line := fmt.Sprintf("status=%d", res.Status)
	if res.Title != "" {
		line += "  title=" + strconv.Quote(res.Title)
	}
	if res.Server != "" {
		line += "  server=" + res.Server
	}
	if len(res.Redirects) > 0 {
		line += "  hops=" + strconv.Itoa(len(res.Redirects))
	}
	if res.Truncated {
		line += "  (body capped at the scope budget — recorded, not parsed past it)"
	}
	return line
}

func scanTLSText(res *observe.TLSResult) string {
	if !res.OK {
		return "result: FAILED — " + res.Failure + "  (recorded as an observation of failure; NOT evidence the asset is absent)"
	}
	line := "tls=" + res.TLSVersion + "  cipher=" + res.CipherSuite
	if res.SubjectCN != "" {
		line += "  subject_cn=" + strconv.Quote(res.SubjectCN)
	}
	if res.IssuerCN != "" {
		line += "  issuer_cn=" + strconv.Quote(res.IssuerCN)
	}
	if res.NotAfter != "" {
		line += "  cert_expiry=" + res.NotAfter
	}
	if len(res.SANDNSNames) > 0 {
		line += "  sans=" + strconv.Itoa(len(res.SANDNSNames))
	}
	return line
}

// renderScanResult prints the shared honest shape for both observers.
// The failure reason itself is carried by the detail line (both text
// helpers embed it verbatim when the observation failed), so no
// separate parameter is needed here.
func renderScanResult(cmd *cobra.Command, protocol, host, ip string, port int,
	ok bool, detail string, scopeID int64, ingested, deduped int) {
	w := cmd.OutOrStdout()
	printf(w, "%s %s (%s)\n", protocol, targetText(host, ip), fmt.Sprintf("port %d", port))
	printf(w, "  %s\n", detail)
	printf(w, "  scope=%d  ingested=%d  deduped=%d  provenance=%s\n",
		scopeID, ingested, deduped, protocolToProvenance(protocol))
	if !ok {
		printf(w, "  note: a failed observation is RECORDED (see gseer search / gseer host); it is never evidence that an asset does not exist\n")
	}
}

func protocolToProvenance(p string) string {
	switch storage.ScopeProtocol(p) {
	case storage.ProtocolHTTP:
		return observe.ProvenanceHTTP
	case storage.ProtocolTLS:
		return observe.ProvenanceTLS
	default:
		return p
	}
}
