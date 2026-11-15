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

package storage

// scope.go — the v0.3.2 active-observation authorization types (the
// engine-agnostic vocabulary shared by the postgres and sqlite stores,
// the observe gateway and the CLI — the same layering the collection
// types use since v0.3.0).
//
// The honesty contract: a scope is an OPERATOR-DECLARED authorization
// record.  GSEER never infers ownership: an operator who adds a scope
// asserts, on their own responsibility, that they own or are otherwise
// authorized to observe the targets the scope covers (docs/SCANNING.md).
// The gateway (internal/observe) enforces scopes default-deny; nothing
// in this file performs authorization by itself.

import (
	crand "crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ScopeKind enumerates the target shapes a scope can cover.
type ScopeKind string

const (
	ScopeKindDomain       ScopeKind = "domain"
	ScopeKindDomainSuffix ScopeKind = "domain_suffix"
	ScopeKindCIDR         ScopeKind = "cidr"
	ScopeKindIP           ScopeKind = "ip"
)

// ErrScopeNotFound — registry lookup miss (both engines return this
// sentinel, the same contract as ErrSourceNotFound).
var ErrScopeNotFound = errors.New("scope not found")

// ErrScopeExists — a create hit the (kind, value) uniqueness constraint.
var ErrScopeExists = errors.New("scope already exists")

// ScopeProtocol enumerates the observer protocols a scope can permit.
type ScopeProtocol string

const (
	ProtocolHTTP ScopeProtocol = "http"
	ProtocolTLS  ScopeProtocol = "tls"
)

// Scope is one authorization record.  A scope is DEAD when revoked or
// expired; the gateway never probes a dead scope's targets.
//
// Default-deny lives in the VALUES: an empty protocol list allows no
// protocol, an empty port list allows no port, and the absence of a
// matching allow-scope denies the target outright.
type Scope struct {
	ID    int64     `json:"id"`
	Kind  ScopeKind `json:"kind"`
	Value string    `json:"value"`
	Mode  string    `json:"mode"` // "allow" (deny rows are recorded but dead-on-arrival)
	Note  string    `json:"note"`

	// Protocols/Ports are the explicit permissions.  Empty = none.
	Protocols []string `json:"protocols"`
	Ports     []int    `json:"ports"`

	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // nil = never expires
	RevokedAt *time.Time `json:"revoked_at,omitempty"` // nil = not revoked

	// Execution limits (one observation run; exact semantics in
	// docs/SCANNING.md and the 0019/0003 migration comments).
	MaxConcurrency int      `json:"max_concurrency"` // simultaneous active observations FOR THIS SCOPE across processes (scan_leases)
	MaxRequests    int      `json:"max_requests"`    // requests/handshakes in one run (redirect hops count)
	MaxTotalBytes  int64    `json:"max_total_bytes"` // response-BODY bytes ACCUMULATED across all hops of one run; 0 = engine default
	Sources        []string `json:"sources,omitempty"`
}

// ParseScopeKind validates and normalizes a scope-kind string.
func ParseScopeKind(s string) (ScopeKind, error) {
	k := ScopeKind(strings.ToLower(strings.TrimSpace(s)))
	switch k {
	case ScopeKindDomain, ScopeKindDomainSuffix, ScopeKindCIDR, ScopeKindIP:
		return k, nil
	default:
		return "", fmt.Errorf("invalid scope kind %q (want domain | domain_suffix | cidr | ip)", s)
	}
}

// ParseScopeProtocols validates a protocol list ("http", "tls").
func ParseScopeProtocols(list []string) ([]string, error) {
	out := make([]string, 0, len(list))
	for _, p := range list {
		p = strings.ToLower(strings.TrimSpace(p))
		switch ScopeProtocol(p) {
		case ProtocolHTTP, ProtocolTLS:
			out = append(out, p)
		default:
			return nil, fmt.Errorf("invalid protocol %q (want http | tls)", p)
		}
	}
	return uniqueStrings(out), nil
}

// ParseScopePorts validates a port list (1–65535 — the same range the
// services table enforces).
func ParseScopePorts(list []int) ([]int, error) {
	out := make([]int, 0, len(list))
	for _, p := range list {
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("invalid port %d (want 1–65535)", p)
		}
		out = append(out, p)
	}
	sort.Ints(out)
	return uniqueInts(out), nil
}

// Active reports whether the scope currently authorizes anything (not
// revoked, not expired, mode allow).  now must be UTC.
func (s Scope) Active(now time.Time) bool {
	if s.Mode != "allow" {
		return false
	}
	if s.RevokedAt != nil && !s.RevokedAt.IsZero() && !s.RevokedAt.After(now) {
		return false
	}
	if s.ExpiresAt != nil && !s.ExpiresAt.IsZero() && !s.ExpiresAt.After(now) {
		return false
	}
	return true
}

// AllowsProtocol reports whether p is explicitly permitted.
func (s Scope) AllowsProtocol(p ScopeProtocol) bool {
	for _, have := range s.Protocols {
		if ScopeProtocol(have) == p {
			return true
		}
	}
	return false
}

// AllowsPort reports whether port n is explicitly permitted.
func (s Scope) AllowsPort(n int) bool {
	for _, have := range s.Ports {
		if have == n {
			return true
		}
	}
	return false
}

// CoversIP reports whether the scope's target covers the given IP
// (exact ip kind, or CIDR containment).  Domain-kind scopes never
// cover an IP.
func (s Scope) CoversIP(ip netip.Addr) bool {
	switch s.Kind {
	case ScopeKindIP:
		addr, err := netip.ParseAddr(s.Value)
		if err != nil {
			return false
		}
		return addr == ip.Unmap()
	case ScopeKindCIDR:
		p, err := netip.ParsePrefix(s.Value)
		if err != nil {
			return false
		}
		return p.Contains(ip.Unmap())
	default:
		return false
	}
}

// CoversHost reports whether the scope's target covers the given
// lowercased, trailing-dot-stripped hostname (exact domain, or any
// name at or under a domain_suffix).
func (s Scope) CoversHost(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if h == "" {
		return false
	}
	switch s.Kind {
	case ScopeKindDomain:
		return strings.TrimSuffix(s.Value, ".") == h
	case ScopeKindDomainSuffix:
		v := strings.TrimSuffix(strings.ToLower(s.Value), ".")
		return h == v || strings.HasSuffix(h, "."+v)
	default:
		return false
	}
}

// ScanAudit is one gateway decision (allow AND deny), appended to
// scan_audits on every authorization answer.
type ScanAudit struct {
	ID         int64          `json:"id"`
	TS         time.Time      `json:"ts"`
	TargetHost string         `json:"target_host,omitempty"`
	TargetIP   string         `json:"target_ip,omitempty"`
	Port       *int           `json:"port,omitempty"`
	Protocol   string         `json:"protocol,omitempty"`
	Decision   string         `json:"decision"` // allow | deny
	Reason     string         `json:"reason"`
	ScopeID    *int64         `json:"scope_id,omitempty"`
	Detail     map[string]any `json:"detail,omitempty"`
}

// ErrScopeBusy — every concurrency-lease slot of the acting scope is
// currently held by other live observations (v0.3.2 security microfix:
// the scope-level max_concurrency enforcement, migration 0019/0003).
// The observers treat this as fail-closed: no probe is sent.
var ErrScopeBusy = errors.New("scope concurrency limit reached")

// ErrLeaseLost — the caller's lease no longer exists in a live state:
// it expired and was stolen by another holder, or it was released.
// Renewal returns this sentinel; the observation must NOT open any new
// connection afterwards (final-security-microfix FIX B).
var ErrLeaseLost = errors.New("concurrency lease lost")

// DefaultScanLeaseTTL bounds how long a held lease survives a crashed
// holder: a dead process's slots become stealable after this interval,
// so stale locks can never accumulate without limit.  Live holders
// renew at TTL/3 (Gateway.StartLeaseRenewal), so a healthy run never
// approaches expiry.
const DefaultScanLeaseTTL = 2 * time.Minute

// NewLeaseToken generates one fresh per-acquisition lease token:
// 128 bits of crypto/rand, hex-encoded.  The token — never the PID,
// hostname or timestamp — is the lease OWNERSHIP identity: release and
// renewal are token-scoped, so a late-releasing old observation in the
// same process cannot touch a newer holder's lease (final-security-
// microfix FIX B).
func NewLeaseToken() (string, error) {
	var b [16]byte
	if _, err := crand.Read(b[:]); err != nil {
		return "", fmt.Errorf("cannot generate lease token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// ScanLease is one held slot of a scope's max_concurrency budget
// (scan_leases table, both engines).  Token is the ownership identity:
// release and renewal only affect the row with the SAME (scope, slot,
// token).  A lease whose expires_at has passed is stealable by the
// next acquire (crash recovery).
type ScanLease struct {
	ScopeID    int64     `json:"scope_id"`
	Slot       int       `json:"slot"`
	Holder     string    `json:"holder"` // diagnostic provenance (host#pid); NOT the ownership key
	Token      string    `json:"token"`  // per-acquisition crypto/rand identity (migration 0020/0004)
	AcquiredAt time.Time `json:"acquired_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ParseScopePortsCSV / scopePortsCSV are the personal-mode storage
// encoding of the ports list (CSV text).  They live here so both the
// sqlite writer and the sqlite reader share one implementation.
func ParseScopePortsCSV(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return []int{}, nil
	}
	parts := strings.Split(s, ",")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid port %q in scope ports list", p)
		}
		out = append(out, n)
	}
	return ParseScopePorts(out)
}

// ScopePortsCSV renders the ports list as the personal-mode CSV text.
func ScopePortsCSV(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

// uniqueInts/uniqueStrings preserve first-seen order (ports list is
// sorted before dedupe; protocols keep caller order).
func uniqueInts(in []int) []int {
	seen := make(map[int]bool, len(in))
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, v := range in {
		if v == "" {
			continue
		}
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
