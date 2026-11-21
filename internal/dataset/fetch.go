// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

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
	"time"
)

// Fetcher downloads dataset artifacts with hard caps: byte limit,
// timeout, credential-redacting errors (userinfo URLs are never echoed),
// and transport enforcement (https, or http on loopback for local
// testing).  Mirrors the updater's download discipline.
type Fetcher struct {
	Client           *http.Client
	ManifestCapBytes int64
	PayloadCapBytes  int64
	// TempDir receives downloaded payloads (default: os.TempDir()).
	TempDir string
}

// NewFetcher builds a Fetcher with the default caps and a timeout-bounded
// client.
func NewFetcher() *Fetcher {
	return &Fetcher{
		Client:           &http.Client{Timeout: 90 * time.Second},
		ManifestCapBytes: DefaultManifestCapBytes,
		PayloadCapBytes:  DefaultPayloadCapBytes,
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

// FetchManifest downloads + parses + validates the manifest.
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
	return m, nil
}

// FetchPayload downloads the payload to a temp file, verifying SIZE and
// SHA-256 while streaming (a mismatch refuses before the database is
// ever touched).  The caller owns the returned file path and must clean
// it up.
func (f *Fetcher) FetchPayload(ctx context.Context, manifestURL string, m *Manifest) (string, error) {
	payloadURL, err := ResolveArtifactURL(manifestURL, m.Payload.Filename)
	if err != nil {
		return "", err
	}
	tmpDir := f.TempDir
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	tmp, err := os.CreateTemp(tmpDir, "gseer-dataset-*.ndjson.gz")
	if err != nil {
		return "", fmt.Errorf("dataset: cannot create the payload temp file: %w", err)
	}
	path := tmp.Name()
	cleanup := func() { _ = tmp.Close(); _ = os.Remove(path) }

	if err := ValidateManifestURL(payloadURL); err != nil {
		cleanup()
		return "", err
	}
	req, rerr := http.NewRequestWithContext(ctx, http.MethodGet, payloadURL, nil)
	if rerr != nil {
		cleanup()
		return "", fmt.Errorf("dataset: cannot build the payload request: %w", rerr)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		cleanup()
		return "", fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel did not answer (%s): %v", redactURL(payloadURL), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		cleanup()
		return "", fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel answered HTTP %d for %s (a fresh channel publishes the artifact; the owner runs the pipeline)",
			resp.StatusCode, redactURL(payloadURL))
	}

	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, f.PayloadCapBytes+1))
	if err != nil {
		cleanup()
		return "", fmt.Errorf("dataset: payload download failed: %w", err)
	}
	if size > f.PayloadCapBytes {
		cleanup()
		return "", fmt.Errorf("dataset: payload exceeds the %d MiB download cap", f.PayloadCapBytes>>20)
	}
	if size != m.Payload.SizeBytes {
		cleanup()
		return "", fmt.Errorf("dataset: payload size mismatch: manifest says %d bytes, downloaded %d", m.Payload.SizeBytes, size)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != m.Payload.SHA256 {
		cleanup()
		return "", fmt.Errorf("E_DATASET_CHECKSUM: payload checksum mismatch: manifest %s, downloaded %s — the artifact is corrupted or tampered; the import was refused and the database was not touched",
			m.Payload.SHA256, got)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("dataset: payload temp file close: %w", err)
	}
	return path, nil
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

// fetchBytes downloads a capped, size-verified body and returns it.
func (f *Fetcher) fetchBytes(ctx context.Context, rawURL string, capBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("dataset: cannot build the manifest request: %w", err)
	}
	resp, err := f.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel did not answer (%s): %v", redactURL(rawURL), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("E_DATASET_UNREACHABLE: the dataset channel answered HTTP %d for %s (a fresh channel publishes the artifact; the owner runs the pipeline)",
			resp.StatusCode, redactURL(rawURL))
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, capBytes+1))
	if err != nil {
		return nil, fmt.Errorf("dataset: manifest download failed: %w", err)
	}
	if int64(len(data)) > capBytes {
		return nil, fmt.Errorf("dataset: manifest exceeds the %d KiB download cap", capBytes>>10)
	}
	return data, nil
}
