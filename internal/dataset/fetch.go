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

package dataset

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Fetcher downloads dataset artifacts with hard caps: byte limit,
// timeout, credential-redacting errors (userinfo URLs are never echoed),
// and transport enforcement (https, or http on loopback for local
// testing).  Mirrors the updater's download discipline.
//
// Resilience (v0.3.3): transient failures (transport errors, HTTP 429 /
// 5xx) are retried with exponential backoff, and an interrupted payload
// download RESUMES from the byte offset already on disk (HTTP Range) —
// a flaky channel costs time, never correctness: size and SHA-256 are
// verified over the complete artifact before anything is trusted.
type Fetcher struct {
	Client           *http.Client
	ManifestCapBytes int64
	PayloadCapBytes  int64
	// TempDir receives downloaded payloads (default: os.TempDir()).
	TempDir string
	// Retries is the number of RETRIES after the first attempt for
	// retryable failures (0 = no retry; default 3 in NewFetcher).
	Retries int
	// Backoff is the delay before the first retry; it doubles each
	// attempt (500ms → 1s → 2s with the default).
	Backoff time.Duration
	// Resume enables the Range-based interrupted-download resume for
	// payloads (default true in NewFetcher).
	Resume bool
}

// NewFetcher builds a Fetcher with the default caps, retry budget, and
// resume behavior.
func NewFetcher() *Fetcher {
	return &Fetcher{
		Client:           &http.Client{Timeout: 90 * time.Second},
		ManifestCapBytes: DefaultManifestCapBytes,
		PayloadCapBytes:  DefaultPayloadCapBytes,
		Retries:          3,
		Backoff:          500 * time.Millisecond,
		Resume:           true,
	}
}

// redactURL strips userinfo from a URL for error display.
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "(unparseable URL)"
	}
	u.User = nil
	return u.String()
}

// FetchManifest downloads + parses + validates the manifest, then
// verifies its Ed25519 signature against the embedded keyring (P0-1):
// an unsigned, foreign-signed, or altered manifest is refused here —
// before the payload URL is ever resolved.
func (f *Fetcher) FetchManifest(ctx context.Context, manifestURL string) (*Manifest, error) {
	if err := ValidateManifestURL(manifestURL); err != nil {
		return nil, err
	}
	data, err := f.fetchBytes(ctx, manifestURL, f.ManifestCapBytes)
	if err != nil {
		return nil, err
	}
	m, err := ParseManifest(data)
	if err != nil {
		return nil, fmt.Errorf("dataset: %w", err)
	}
	if err := VerifyTrusted(data, m); err != nil {
		return nil, fmt.Errorf("dataset: %w", err)
	}
	return m, nil
}

// FetchPayload downloads the payload to a temp file, verifying SIZE and
// SHA-256 over the COMPLETE artifact while streaming (a mismatch refuses
// before the database is ever touched).  When Resume is on, an
// interrupted download continues from the byte offset of the previous
// attempt's part file (HTTP Range; a server that ignores Range simply
// restarts from zero).  The caller owns the returned file path and must
// clean it up.
func (f *Fetcher) FetchPayload(ctx context.Context, manifestURL string, m *Manifest) (string, error) {
	payloadURL, err := ResolveArtifactURL(manifestURL, m.Payload.Filename)
	if err != nil {
		return "", err
	}
	tmpDir := f.TempDir
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	// Deterministic part-file name: the payload's checksum prefixes it,
	// so a resume only ever continues the SAME artifact — never a mixed
	// pair of manifest and payload from different versions.
	part := filepath.Join(tmpDir, "gseer-dataset-"+m.Payload.SHA256[:16]+".part")
	offset := int64(0)
	if f.Resume {
		if fi, serr := os.Stat(part); serr == nil && fi.Size() > 0 {
			offset = fi.Size()
		}
	}
	// Append only when actually resuming; otherwise truncate — a stale
	// part file (Resume off, or a zero offset) must never poison the
	// artifact.  O_APPEND keeps every write at the file's end, so the
	// resumed tail continues exactly where the interrupted attempt
	// stopped.
	openFlags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if offset == 0 {
		openFlags |= os.O_TRUNC
	}
	tmp, err := os.OpenFile(part, openFlags, 0o600)
	if err != nil {
		return "", fmt.Errorf("dataset: cannot create the payload temp file: %w", err)
	}
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(part) }

	if err := ValidateManifestURL(payloadURL); err != nil {
		cleanup()
		return "", err
	}
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, payloadURL, nil)
	if rerr != nil {
		cleanup()
		return "", fmt.Errorf("dataset: cannot build the payload request: %w", rerr)
	}
	if offset > 0 {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(offset, 10)+"-")
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		// Keep the part file: the next update resumes from it.
		_ = tmp.Close()
		return "", fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel did not answer (%s): %v", redactURL(payloadURL), err)
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusPartialContent:
		// Range honored: continue appending after the carried offset.
	case resp.StatusCode == http.StatusOK && offset == 0:
		// Plain full download (no resume carried).
	case offset > 0 && resp.StatusCode == http.StatusOK:
		// Server ignored the Range: restart from zero (O_APPEND keeps
		// writes at the file end; truncated, that is byte 0).
		offset = 0
		if err := tmp.Truncate(0); err != nil {
			cleanup()
			return "", fmt.Errorf("dataset: cannot restart the payload temp file: %w", err)
		}
	default:
		// A ranged request that comes back neither 200 nor 206 (404,
		// 410, 416 …) means the artifact is not resumable here: drop
		// the stale part and surface the plain channel error.
		cleanup()
		return "", fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel answered HTTP %d for %s (a fresh channel publishes the artifact; the owner runs the pipeline)",
			resp.StatusCode, redactURL(payloadURL))
	}

	remaining := m.Payload.SizeBytes - offset
	if remaining < 0 {
		cleanup()
		return "", fmt.Errorf("dataset: the resumed part file is larger than the manifest's payload size; the partial download was discarded")
	}
	size, err := io.Copy(tmp, io.LimitReader(resp.Body, remaining+1))
	if err != nil {
		// Keep the part file: the next update resumes from it.
		_ = tmp.Close()
		return "", fmt.Errorf("dataset: payload download failed (progress kept for resume): %w", err)
	}
	if size != remaining {
		cleanup()
		return "", fmt.Errorf("dataset: payload download incomplete: expected %d bytes total, got %d (the part file was discarded)",
			m.Payload.SizeBytes, offset+size)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(part)
		return "", fmt.Errorf("dataset: payload temp file close: %w", err)
	}

	// Verify the COMPLETE artifact: size + SHA-256 streamed from disk,
	// covering both the resumed prefix and the freshly downloaded tail.
	fh, err := os.Open(part)
	if err != nil {
		_ = os.Remove(part)
		return "", fmt.Errorf("dataset: cannot reopen the payload temp file: %w", err)
	}
	h := sha256.New()
	total, err := io.Copy(h, io.LimitReader(fh, f.PayloadCapBytes+1))
	_ = fh.Close()
	if err != nil {
		_ = os.Remove(part)
		return "", fmt.Errorf("dataset: payload verification failed: %w", err)
	}
	if total > f.PayloadCapBytes {
		_ = os.Remove(part)
		return "", fmt.Errorf("dataset: payload exceeds the %d MiB download cap", f.PayloadCapBytes>>20)
	}
	if total != m.Payload.SizeBytes {
		_ = os.Remove(part)
		return "", fmt.Errorf("dataset: payload size mismatch: manifest says %d bytes, downloaded %d", m.Payload.SizeBytes, total)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != m.Payload.SHA256 {
		_ = os.Remove(part)
		return "", fmt.Errorf("E_DATASET_CHECKSUM: payload checksum mismatch: manifest %s, downloaded %s — the artifact is corrupted or tampered; the import was refused and the database was not touched",
			m.Payload.SHA256, got)
	}

	// Finalize: rename the verified part to the payload's canonical
	// file name (the import layer refuses non-.ndjson.gz paths; the
	// base() keeps a hostile manifest filename from leaving TempDir).
	name := filepath.Base(m.Payload.Filename)
	if !strings.HasSuffix(name, ".ndjson.gz") {
		_ = os.Remove(part)
		return "", fmt.Errorf("dataset: manifest payload filename %q is not a .ndjson.gz artifact", name)
	}
	final := filepath.Join(tmpDir, name)
	if err := os.Rename(part, final); err != nil {
		_ = os.Remove(part)
		return "", fmt.Errorf("dataset: cannot finalize the payload file: %w", err)
	}
	return final, nil
}

// ResolveArtifactURL resolves the payload URL relative to the manifest
// URL (same directory, like the updater's artifact resolution).
func ResolveArtifactURL(manifestURL, filename string) (string, error) {
	base, err := url.Parse(manifestURL)
	if err != nil || base.Path == "" {
		return "", fmt.Errorf("dataset: cannot resolve the payload URL from %q", manifestURL)
	}
	base.Path = filepath.ToSlash(filepath.Join(filepath.Dir(base.Path), filename))
	return base.String(), nil
}

// fetchBytes downloads a capped, size-verified body and returns it,
// retrying retryable failures (transport errors and HTTP 429/5xx) with
// exponential backoff — a flaky channel is given every honest chance
// before the run reports E_DATASET_UNREACHABLE.
func (f *Fetcher) fetchBytes(ctx context.Context, rawURL string, capBytes int64) ([]byte, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		if attempt > 0 {
			delay := f.Backoff << (attempt - 1) // 500ms → 1s → 2s …
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("dataset: manifest fetch cancelled while backing off: %w", ctx.Err())
			case <-time.After(delay):
			}
		}
		data, retryable, err := f.tryFetchBytes(ctx, rawURL, capBytes)
		if err == nil {
			return data, nil
		}
		lastErr = err
		if !retryable || attempt >= f.Retries {
			return nil, lastErr
		}
	}
}

// tryFetchBytes performs ONE download attempt; retryable reports
// whether the failure is transient (transport error, 429, 5xx).
func (f *Fetcher) tryFetchBytes(ctx context.Context, rawURL string, capBytes int64) (data []byte, retryable bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("dataset: cannot build the manifest request: %w", err)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, true, fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel did not answer (%s): %v", redactURL(rawURL), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusTooManyRequests ||
		resp.StatusCode == http.StatusInternalServerError ||
		resp.StatusCode == http.StatusBadGateway ||
		resp.StatusCode == http.StatusServiceUnavailable ||
		resp.StatusCode == http.StatusGatewayTimeout {
		return nil, true, fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel answered HTTP %d for %s (retrying with backoff)",
			resp.StatusCode, redactURL(rawURL))
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel answered HTTP %d for %s (a fresh channel publishes the artifact; the owner runs the pipeline)",
			resp.StatusCode, redactURL(rawURL))
	}
	data, err = io.ReadAll(io.LimitReader(resp.Body, capBytes+1))
	if err != nil {
		return nil, true, fmt.Errorf("dataset: manifest download failed: %w", err)
	}
	if int64(len(data)) > capBytes {
		return nil, false, fmt.Errorf("dataset: manifest exceeds the %d KiB download cap", capBytes>>10)
	}
	return data, false, nil
}
