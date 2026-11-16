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

package observe

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/Lutfifakee-Project/gseer/internal/storage"
)

// tls.go — the ACTIVE TLS observer (v0.3.2): one explicit,
// gateway-authorized TLS HANDSHAKE against a scoped target (no HTTP
// request is sent — the observers are separate by contract), recording
// the certificate and handshake state as a service-level fact whose
// evidence keys feed the existing latest_tls view (tls_version /
// cert_subject_cn / cert_issuer_cn / cert_expiry land directly in the
// search_index tls_* columns).
//
// Honesty contract:
//   - the certificate is CAPTURED, never evaluated for trust: a
//     self-signed or mismatched certificate is still recorded verbatim
//     (it IS the data — the operator decides what it means);
//   - the handshake dials ONLY the gateway-validated address;
//   - a handshake failure is an OBSERVATION OF FAILURE, never absence.

// SourceTLS is the observations.source row the TLS observer runs under.
const SourceTLS = "scan-tls"

// ProvenanceTLS is the observations.provenance label for TLS scans.
const ProvenanceTLS = "scan-tls"

// serviceProtocolTLS is the services.protocol value recorded by the TLS
// observer (the service SPEAKS https on that port).
const serviceProtocolTLS = "https"

// TLSObserver runs gateway-authorized TLS handshakes.
type TLSObserver struct {
	GW *Gateway
	// Timeout bounds dial + handshake.
	Timeout time.Duration
}

// TLSResult is one TLS observation run, as the CLI prints it.
type TLSResult struct {
	Protocol    string   `json:"protocol"`
	Host        string   `json:"host"`
	IP          string   `json:"ip"`
	Port        int      `json:"port"`
	OK          bool     `json:"ok"`
	Failure     string   `json:"failure,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	CipherSuite string   `json:"cipher_suite,omitempty"`
	SubjectCN   string   `json:"cert_subject_cn,omitempty"`
	IssuerCN    string   `json:"cert_issuer_cn,omitempty"`
	NotAfter    string   `json:"cert_expiry,omitempty"`
	SANDNSNames []string `json:"cert_sans_dns,omitempty"`
	Serial      string   `json:"cert_serial,omitempty"`
	Facts       int      `json:"facts"`
	Ingested    int      `json:"ingested"`
	Deduped     int      `json:"deduped"`
	ScopeID     int64    `json:"scope_id,omitempty"`
	Provenance  string   `json:"provenance"`
}

// Run performs one TLS handshake observation.  Authorization failures
// return an error (no probe fires); observation-level failures are
// RECORDED as failed-observation facts and reported via OK/Failure.
func (o *TLSObserver) Run(ctx context.Context, host string, port int) (*TLSResult, error) {
	res := &TLSResult{Protocol: string(storage.ProtocolTLS), Port: port, Provenance: ProvenanceTLS}

	// 1. Gateway (the dial below re-checks by dialing the pinned IP only).
	dec, aerr := o.GW.Authorize(ctx, host, port, storage.ProtocolTLS)
	if aerr != nil {
		return res, aerr
	}
	res.Host = dec.Host
	res.IP = ipText(dec.IP)
	res.ScopeID = dec.Scope.ID

	// 2. Source row (idempotent).
	sourceID, serr := o.GW.Store.EnsureSource(ctx, SourceTLS, "scan-tls", HTTPTermsRef, map[string]any{
		"scope_id": dec.Scope.ID,
		"target":   net.JoinHostPort(dec.Host, strconv.Itoa(port)),
	})
	if serr != nil {
		return res, fmt.Errorf("cannot ensure the %s source row: %v", SourceTLS, serr)
	}

	// 2b. Concurrency lease (v0.3.2 microfix FIX D + final-security-
	// microfix FIX B): one of the scope's max_concurrency slots,
	// cross-process via scan_leases with a per-acquisition TOKEN and a
	// renewal heartbeat (TTL/3).  Busy or any storage failure FAILS
	// CLOSED (no connection).  Released (token-scoped) at run end; the
	// TTL bounds a leaked row if the process dies.
	lease, lerr := o.GW.AcquireLease(ctx, dec)
	if lerr != nil {
		return res, lerr
	}
	defer o.GW.ReleaseLease(ctx, lease)
	leaseGuard := o.GW.StartLeaseRenewal(ctx, lease)
	defer leaseGuard.Stop()

	now := o.GW.now()
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}

	// 2c. FIX B: re-validate the ORIGINAL hostname + the pinned address
	// against the CURRENT registry immediately before the connection —
	// domain/domain_suffix scopes keep matching by NAME, ip/cidr scopes
	// and the restricted-address policy by the address that will
	// actually be dialed (revocation or expiry between the initial
	// authorization and the dial denies here, with the denial audited;
	// no DNS is consulted — the pin stands).  The residual window
	// between this registry read and the connect syscall is irreducible
	// in userspace and documented in docs/SCANNING.md — never
	// overstated.
	if leaseGuard.Lost() {
		return res, fmt.Errorf("E_SCOPE_BUSY: concurrency lease lost (renewal failure) — FAIL CLOSED, no connection: %w", storage.ErrLeaseLost)
	}
	if _, rerr := o.GW.Revalidate(ctx, dec.Host, dec.IP, port, storage.ProtocolTLS); rerr != nil {
		return res, rerr
	}
	// FIX B: the LAST gate — re-check the lease immediately before the
	// socket connect (the renewal heartbeat may have failed while the
	// pre-dial authorization ran).
	if leaseGuard.Lost() {
		return res, fmt.Errorf("E_SCOPE_BUSY: concurrency lease lost (renewal failure) — FAIL CLOSED, no connection: %w", storage.ErrLeaseLost)
	}

	// 3. Dial the VALIDATED address; the hostname goes to SNI only.
	rawConn, derr := (&net.Dialer{Timeout: timeout}).DialContext(ctx, "tcp",
		net.JoinHostPort(dec.IP.String(), strconv.Itoa(port)))
	failure := ""
	var (
		tlsVersion string
		cipher     string
		subjectCN  string
		issuerCN   string
		notAfter   string
		sans       []string
		serial     string
	)
	if derr == nil {
		cfg := &tls.Config{
			ServerName: dec.Host,
			// Certificates are CAPTURED here, not evaluated: asset
			// observation wants what the server actually presented,
			// including self-signed and name-mismatched certificates.
			InsecureSkipVerify: true, // #nosec G402 -- deliberate capture-not-verify design (docs/SCANNING.md §capture-not-verify): the observation records the presented certificate without evaluating trust
			MinVersion:         tls.VersionTLS10,
		}
		tconn := tls.Client(rawConn, cfg)
		hsCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		herr := tconn.HandshakeContext(hsCtx)
		if herr != nil {
			failure = "tls handshake: " + herr.Error()
		} else {
			cs := tconn.ConnectionState()
			tlsVersion = tls.VersionName(cs.Version)
			cipher = tls.CipherSuiteName(cs.CipherSuite)
			if len(cs.PeerCertificates) > 0 {
				leaf := cs.PeerCertificates[0]
				subjectCN = leaf.Subject.CommonName
				issuerCN = leaf.Issuer.CommonName
				notAfter = leaf.NotAfter.UTC().Format(time.RFC3339)
				sans = leaf.DNSNames
				serial = leaf.SerialNumber.Text(16)
			}
		}
		_ = tconn.Close()
	} else {
		failure = errText(derr)
	}

	// 4. Honest evidence + facts.
	evidence := map[string]any{
		"tls": map[string]any{
			"version":         tlsVersion,
			"cipher_suite":    cipher,
			"cert_subject_cn": subjectCN,
			"cert_issuer_cn":  issuerCN,
		},
		"scan": map[string]any{
			"scope_id":    dec.Scope.ID,
			"target":      net.JoinHostPort(dec.Host, strconv.Itoa(port)),
			"observed_ip": dec.IP.String(),
		},
		"confidence": confidenceFor(failure),
	}
	if sans != nil {
		evidence["tls"].(map[string]any)["cert_sans_dns"] = sans
	}
	if serial != "" {
		evidence["tls"].(map[string]any)["cert_serial"] = serial
	}
	if failure != "" {
		evidence["scan"].(map[string]any)["result"] = "failed"
		evidence["scan"].(map[string]any)["error"] = failure
	} else {
		evidence["scan"].(map[string]any)["result"] = "observed"
		evidence["tls"].(map[string]any)["cert_expiry"] = notAfter
	}

	facts := scanFacts(now, sourceID, SourceTLS, ProvenanceTLS, dec.Host, dec.IP, port,
		serviceProtocolTLS, evidence, dec.Scope.ID)
	stats, ierr := o.GW.Store.IngestFacts(ctx, facts)
	if ierr != nil {
		return res, fmt.Errorf("cannot ingest the observation facts: %v", ierr)
	}

	res.OK = failure == ""
	res.Failure = failure
	res.TLSVersion = tlsVersion
	res.CipherSuite = cipher
	res.SubjectCN = subjectCN
	res.IssuerCN = issuerCN
	res.NotAfter = notAfter
	res.SANDNSNames = sans
	res.Serial = serial
	res.Facts = len(facts)
	res.Ingested = stats.AssetsInserted + stats.ServicesInserted + stats.ObservationsInserted
	res.Deduped = stats.ObservationsDeduped
	return res, nil
}
