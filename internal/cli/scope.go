// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// scope.go — `gseer scope` (v0.3.2): the operator's authorization
// registry for active observation.  A scope is an OPERATOR-DECLARED
// record: adding one asserts, on the operator's own responsibility,
// that they own or are otherwise authorized to observe the targets it
// covers.  GSEER never infers ownership.  The gateway (internal/observe)
// enforces scopes DEFAULT-DENY — a target without a live, protocol- and
// port-permitting scope is never probed, and every decision (allow AND
// deny) is audited.
//
// Nothing here collects or observes: `gseer scope` only manages the
// registry.  The observation itself is `gseer scan` — an explicit
// command, like `gseer collect`.

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/observe"
	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// observeBackend is the storage surface `gseer scope` / `gseer scan`
// need, over the canonical storage types.  BOTH engines satisfy it
// (compile-time assertions below — the same pattern registry.go pins).
type observeBackend interface {
	observe.Store
	CreateScope(ctx context.Context, sc *storage.Scope) (int64, error)
	GetScope(ctx context.Context, id int64) (storage.Scope, error)
	RevokeScope(ctx context.Context, id int64, when time.Time) (bool, error)
	ListScanAudits(ctx context.Context, limit int) ([]storage.ScanAudit, error)
}

func registerScopeCmd(root *cobra.Command) {
	scope := &cobra.Command{
		Use:   "scope",
		Short: "Manage the active-observation authorization registry (default-deny; nothing scans until you run gseer scan)",
		Args:  cobra.NoArgs,
		Long: `Manage GSEER's active-observation scope registry.

A scope is an operator-declared authorization record: by adding one you
assert that you own — or are otherwise authorized to observe — the
targets it covers.  GSEER never infers ownership and never probes a
target without a live scope.

A scope is DEAD (never probed) when:
  - it is revoked        (gseer scope revoke <id>)
  - it is expired        (--expires-at in the past)
  - its mode is "deny"   (kept for registry completeness)
and even a live scope permits ONLY:
  - the protocols it lists (--protocols http and/or tls)
  - the ports it lists    (--ports 80,443,...)

Default-deny: a target with no matching scope is refused by the gateway
(E_SCOPE_DENIED, exit 5) and the refusal is audited (gseer scope audit).

Private/loopback addresses are reachable ONLY with a scope that
explicitly covers the address or range (e.g. --kind cidr --value
127.0.0.1/32) — that is the supported way to observe a service you run
yourself.

Examples:
  gseer scope add cidr 127.0.0.1/32 --protocols http,tls --ports 8080,8443 \\
      --note "my local dev server"`,
	}
	scope.AddCommand(newScopeAddCmd(), newScopeListCmd(), newScopeRevokeCmd(), newScopeAuditCmd())
	root.AddCommand(scope)
}

type scopeAddFlags struct {
	protocols      []string
	ports          string
	note           string
	expiresAt      string
	maxConcurrency int
	maxRequests    int
	maxBytes       int64
}

func newScopeAddCmd() *cobra.Command {
	f := &scopeAddFlags{}
	cmd := &cobra.Command{
		Use:   "add <kind> <value>",
		Short: "Add an authorization scope (you assert the authorization basis)",
		Args:  cobra.ExactArgs(2),
		RunE:  func(cmd *cobra.Command, args []string) error { return runScopeAdd(cmd, args[0], args[1], f) },
	}
	cmd.Flags().StringSliceVar(&f.protocols, "protocols", nil,
		"protocols the scope permits: http and/or tls (required; empty permits nothing)")
	cmd.Flags().StringVar(&f.ports, "ports", "",
		"ports the scope permits, comma-separated (required; e.g. 80,443)")
	cmd.Flags().StringVar(&f.note, "note", "", "why this scope exists (audit metadata)")
	cmd.Flags().StringVar(&f.expiresAt, "expires-at", "",
		"UTC expiry (RFC 3339, e.g. 2026-12-31T23:59:59Z); empty = never expires")
	cmd.Flags().IntVar(&f.maxConcurrency, "max-concurrency", 1,
		"max simultaneous active observations for this scope, ACROSS PROCESSES (lease-enforced; a further scan fails with E_SCOPE_BUSY)")
	cmd.Flags().IntVar(&f.maxRequests, "max-requests", 1, "max HTTP requests per scan run (redirect hops count)")
	cmd.Flags().Int64Var(&f.maxBytes, "max-bytes", 0,
		"max response-BODY bytes per scan run, ACCUMULATED across every redirect hop (0 = engine default)")
	return cmd
}

func runScopeAdd(cmd *cobra.Command, kindArg, valueArg string, f *scopeAddFlags) error {
	kind, kerr := storage.ParseScopeKind(kindArg)
	if kerr != nil {
		return fmt.Errorf("E_INVALID_INPUT: %v\nTry: gseer scope add cidr 127.0.0.1/32 --protocols http --ports 8080", kerr)
	}
	ports, perr := parseScopePortsFlag(f.ports)
	if perr != nil {
		return fmt.Errorf("E_INVALID_INPUT: %v", perr)
	}
	sc := &storage.Scope{
		Kind:           kind,
		Value:          valueArg,
		Mode:           "allow",
		Note:           f.note,
		Protocols:      f.protocols,
		Ports:          ports,
		MaxConcurrency: f.maxConcurrency,
		MaxRequests:    f.maxRequests,
		MaxTotalBytes:  f.maxBytes,
	}
	if f.expiresAt != "" {
		t, terr := time.Parse(time.RFC3339, f.expiresAt)
		if terr != nil {
			return fmt.Errorf("E_INVALID_INPUT: --expires-at must be RFC 3339 UTC (e.g. 2026-12-31T23:59:59Z): %v", terr)
		}
		if !t.After(time.Now()) {
			return fmt.Errorf("E_INVALID_INPUT: --expires-at is in the past — a scope born dead authorizes nothing; use a future expiry")
		}
		sc.ExpiresAt = &t
	}

	store, closer, err := openObserveStore(cmd)
	if err != nil {
		return err
	}
	defer closer()

	id, cerr := store.CreateScope(commandContext(cmd), sc)
	if cerr != nil {
		return cerr
	}
	w := cmd.OutOrStdout()
	printf(w, "Registered scope id=%d %s %s protocols=%s ports=%s expires=%s (allow; default-deny is unaffected: only this scope's targets, protocols and ports can be probed)\n",
		id, sc.Kind, sc.Value,
		strings.Join(sc.Protocols, ","), scopePortsText(sc.Ports), expiresText(sc.ExpiresAt))
	printf(w, "Next: gseer scan http --target %s --port %d   (explicit; the gateway still re-validates every hop)\n",
		sc.Value, firstPortOr(sc.Ports, 80))
	return nil
}

func newScopeListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List scopes (history included: revoked and expired rows stay visible)",
		Args:  cobra.NoArgs,
		RunE:  runScopeList,
	}
}

func runScopeList(cmd *cobra.Command, args []string) error {
	store, closer, err := openObserveStore(cmd)
	if err != nil {
		return err
	}
	defer closer()

	scopes, lerr := store.ListScopes(commandContext(cmd))
	if lerr != nil {
		printf(cmd.ErrOrStderr(), "E_DB: %v\n", lerr)
		exitWith(ExitUnavailable)
		return nil
	}
	now := time.Now().UTC()
	w := cmd.OutOrStdout()
	if len(scopes) == 0 {
		printf(w, "No scopes registered. Active observation is FULLY DENIED until you add one\n(gseer scope add <kind> <value> --protocols ... --ports ...).\n")
		return nil
	}
	printf(w, "ID  KIND  VALUE  STATE  PROTOCOLS  PORTS  EXPIRES  NOTE\n")
	for _, sc := range scopes {
		state := "allow-active"
		switch {
		case sc.Mode != "allow":
			state = "deny-mode"
		case sc.RevokedAt != nil:
			state = "revoked"
		case sc.ExpiresAt != nil && !sc.ExpiresAt.After(now):
			state = "expired"
		}
		printf(w, "%d  %s  %s  %s  %s  %s  %s  %s\n",
			sc.ID, sc.Kind, sc.Value, state,
			strings.Join(sc.Protocols, ","), scopePortsText(sc.Ports),
			expiresText(sc.ExpiresAt), sc.Note)
	}
	return nil
}

func newScopeRevokeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke a scope (takes effect on the next connection; the row stays as history)",
		Args:  cobra.ExactArgs(1),
		RunE:  runScopeRevoke,
	}
}

func runScopeRevoke(cmd *cobra.Command, args []string) error {
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("E_INVALID_INPUT: scope id must be a positive integer (gseer scope list shows the ids)")
	}
	store, closer, err := openObserveStore(cmd)
	if err != nil {
		return err
	}
	defer closer()

	revoked, rerr := store.RevokeScope(commandContext(cmd), id, time.Now().UTC())
	if rerr != nil {
		return rerr
	}
	w := cmd.OutOrStdout()
	if !revoked {
		printf(w, "Scope %d was already revoked (or does not exist): gseer scope list shows the states.\n", id)
		return nil
	}
	printf(w, "Revoked scope %d. In-flight connections finish their current hop; every NEW connection is denied (audited).\n", id)
	return nil
}

func newScopeAuditCmd() *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Show recent gateway decisions (allow AND deny — the authorization trail)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, closer, err := openObserveStore(cmd)
			if err != nil {
				return err
			}
			defer closer()
			recs, aerr := store.ListScanAudits(commandContext(cmd), limit)
			if aerr != nil {
				printf(cmd.ErrOrStderr(), "E_DB: %v\n", aerr)
				exitWith(ExitUnavailable)
				return nil
			}
			w := cmd.OutOrStdout()
			if len(recs) == 0 {
				printf(w, "No gateway decisions recorded yet.\n")
				return nil
			}
			printf(w, "TS  DECISION  TARGET  PORT  PROTOCOL  REASON  SCOPE\n")
			for _, r := range recs {
				port := "-"
				if r.Port != nil {
					port = strconv.Itoa(*r.Port)
				}
				scope := "-"
				if r.ScopeID != nil {
					scope = strconv.FormatInt(*r.ScopeID, 10)
				}
				printf(w, "%s  %s  %s  %s  %s  %s  %s\n",
					r.TS.UTC().Format(time.RFC3339), r.Decision,
					targetText(r.TargetHost, r.TargetIP), port, r.Protocol,
					r.Reason, scope)
			}
			return nil
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 20, "how many recent decisions to show")
	return cmd
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func parseScopePortsFlag(csvFlag string) ([]int, error) {
	if strings.TrimSpace(csvFlag) == "" {
		return nil, fmt.Errorf("--ports is required: a scope permits explicit ports only (default-deny means an empty port list would authorize nothing)")
	}
	var out []int
	for _, part := range strings.Split(csvFlag, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("invalid port %q in --ports", part)
		}
		out = append(out, n)
	}
	ports, verr := storage.ParseScopePorts(out)
	if verr != nil {
		return nil, verr
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("--ports resolved to an empty list")
	}
	return ports, nil
}

func scopePortsText(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

func expiresText(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func firstPortOr(ports []int, def int) int {
	if len(ports) > 0 {
		return ports[0]
	}
	return def
}

func targetText(host, ip string) string {
	if host != "" && ip != "" && host != ip {
		return host + " (" + ip + ")"
	}
	if host != "" {
		return host
	}
	return ip
}
