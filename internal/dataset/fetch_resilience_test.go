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

// fetch_resilience_test.go — v0.3.3 pipeline-resilience proofs:
// retry with backoff on transient failures, Range-based resume of an
// interrupted payload download, restart when a server ignores Range,
// and the corrupt-tail refusal (checksum over the COMPLETE artifact).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testFetcher(server *httptest.Server) *Fetcher {
	f := NewFetcher()
	f.Client = server.Client()
	f.TempDir = tTempDir()
	f.Backoff = 1 * time.Millisecond
	return f
}

// tTempDir returns a per-test temp dir (kept tiny; tests create many).
func tTempDir() string {
	dir, err := os.MkdirTemp("", "gseer-fetchtest-*")
	if err != nil {
		panic(err)
	}
	return dir
}

func TestFetchBytesRetriesOnServiceUnavailable(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		if hits < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("manifest-body"))
	}))
	defer server.Close()

	f := testFetcher(server)
	f.Retries = 3
	data, err := f.fetchBytes(context.Background(), server.URL, 64<<10)
	if err != nil {
		t.Fatalf("fetchBytes after transient 503s: %v", err)
	}
	if string(data) != "manifest-body" {
		t.Fatalf("unexpected body %q", data)
	}
	if hits != 3 {
		t.Fatalf("retries: got %d attempts, want 3", hits)
	}
}

func TestFetchBytesRetriesExhausted(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	f := testFetcher(server)
	f.Retries = 2
	_, err := f.fetchBytes(context.Background(), server.URL, 64<<10)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_UNREACHABLE") {
		t.Fatalf("want E_DATASET_UNREACHABLE after retries, got %v", err)
	}
	if hits != 3 { // 1 initial + 2 retries
		t.Fatalf("attempts: got %d, want 3", hits)
	}
}

func TestFetchBytesNoRetryOnPermanentFailure(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	f := testFetcher(server)
	_, err := f.fetchBytes(context.Background(), server.URL, 64<<10)
	if err == nil {
		t.Fatal("want an error on 404")
	}
	if hits != 1 {
		t.Fatalf("404 must not be retried: got %d attempts, want 1", hits)
	}
}

func TestFetchBytesNoRetryWhenDisabled(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	f := testFetcher(server)
	f.Retries = 0
	_, err := f.fetchBytes(context.Background(), server.URL, 64<<10)
	if err == nil || hits != 1 {
		t.Fatalf("Retries=0 must attempt once: attempts=%d err=%v", hits, err)
	}
}

// payloadFixture builds a deterministic payload + a manifest describing it.
func payloadFixture(n int) ([]byte, *Manifest) {
	payload := make([]byte, n)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	sum := sha256.Sum256(payload)
	m := &Manifest{
		SchemaVersion:  SchemaVersion,
		DatasetVersion: 99,
		Payload: PayloadInfo{
			Filename:  "dataset-v99.ndjson.gz",
			SizeBytes: int64(n),
			SHA256:    hex.EncodeToString(sum[:]),
			Records:   1,
		},
	}
	return payload, m
}

func partPathFor(dir string, m *Manifest) string {
	return filepath.Join(dir, "gseer-dataset-"+m.Payload.SHA256[:16]+".part")
}

// finalPathFor is the canonical payload path FetchPayload must return
// after verifying + finalizing the artifact (the import layer refuses
// non-.ndjson.gz paths).
func finalPathFor(dir string, m *Manifest) string {
	return filepath.Join(dir, filepath.Base(m.Payload.Filename))
}

// rangeServer serves the payload with proper Range support (206) and
// counts how often a ranged request arrived.
func rangeServer(payload []byte, rangedHits *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rng := r.Header.Get("Range"); rng != "" {
			*rangedHits++
			var start int64
			if _, err := fmt.Sscanf(rng, "bytes=%d-", &start); err != nil || start <= 0 || start >= int64(len(payload)) {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(payload)-1, len(payload)))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(payload[start:])
			return
		}
		_, _ = w.Write(payload)
	}))
}

func TestFetchPayloadResumesInterruptedDownload(t *testing.T) {
	payload, m := payloadFixture(1000)
	var rangedHits int
	server := rangeServer(payload, &rangedHits)
	defer server.Close()

	dir := tTempDir()
	f := testFetcher(server)
	f.TempDir = dir

	// Simulate a previous interrupted attempt: the first 400 bytes are
	// already on disk.
	part := partPathFor(dir, m)
	if err := os.WriteFile(part, payload[:400], 0o600); err != nil {
		t.Fatal(err)
	}

	path, err := f.FetchPayload(context.Background(), server.URL+"/central-dataset/gseer-dataset-manifest.json", m)
	if err != nil {
		t.Fatalf("resume failed: %v", err)
	}
	if path != finalPathFor(dir, m) {
		t.Fatalf("expected the finalized payload path, got %s", path)
	}
	if rangedHits != 1 {
		t.Fatalf("expected exactly one ranged request, got %d", rangedHits)
	}
	if _, statErr := os.Stat(part); !os.IsNotExist(statErr) {
		t.Fatalf("the part file must be renamed away after success, stat err=%v", statErr)
	}
	got, err := os.ReadFile(finalPathFor(dir, m))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("resumed payload mismatches: %d bytes, want %d", len(got), len(payload))
	}
}

func TestFetchPayloadRestartsWhenServerIgnoresRange(t *testing.T) {
	payload, m := payloadFixture(1000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Ignores Range on purpose: answers 200 with the full body.
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	dir := tTempDir()
	f := testFetcher(server)
	f.TempDir = dir
	part := partPathFor(dir, m)
	if err := os.WriteFile(part, payload[:400], 0o600); err != nil {
		t.Fatal(err)
	}

	path, err := f.FetchPayload(context.Background(), server.URL+"/central-dataset/gseer-dataset-manifest.json", m)
	if err != nil {
		t.Fatalf("restart-after-ignored-range failed: %v", err)
	}
	_ = path
	got, _ := os.ReadFile(finalPathFor(dir, m))
	if string(got) != string(payload) {
		t.Fatalf("payload after restart mismatches (got %d bytes)", len(got))
	}
}

func TestFetchPayloadCorruptTailRefusedAndDiscarded(t *testing.T) {
	payload, m := payloadFixture(1000)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "" {
			// Serve a WRONG tail: a tampered last byte.
			w.WriteHeader(http.StatusPartialContent)
			bad := append([]byte{}, payload[400:]...)
			bad[len(bad)-1] ^= 0xff
			_, _ = w.Write(bad)
			return
		}
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	dir := tTempDir()
	f := testFetcher(server)
	f.TempDir = dir
	part := partPathFor(dir, m)
	if err := os.WriteFile(part, payload[:400], 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := f.FetchPayload(context.Background(), server.URL+"/central-dataset/gseer-dataset-manifest.json", m)
	if err == nil || !strings.Contains(err.Error(), "E_DATASET_CHECKSUM") {
		t.Fatalf("corrupt tail must be refused with E_DATASET_CHECKSUM, got %v", err)
	}
	if _, statErr := os.Stat(part); !os.IsNotExist(statErr) {
		t.Fatalf("the corrupt part file must be discarded, stat err=%v", statErr)
	}
}

func TestFetchPayloadStalePartIgnoredWhenResumeOff(t *testing.T) {
	payload, m := payloadFixture(1000)
	server := rangeServer(payload, new(int))
	defer server.Close()

	dir := tTempDir()
	f := testFetcher(server)
	f.TempDir = dir
	f.Resume = false
	part := partPathFor(dir, m)
	if err := os.WriteFile(part, payload[:400], 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := f.FetchPayload(context.Background(), server.URL+"/central-dataset/gseer-dataset-manifest.json", m); err != nil {
		t.Fatalf("no-resume fetch failed: %v", err)
	}
	if _, statErr := os.Stat(part); !os.IsNotExist(statErr) {
		t.Fatalf("the part file must be renamed away after success, stat err=%v", statErr)
	}
	got, _ := os.ReadFile(finalPathFor(dir, m))
	if string(got) != string(payload) {
		t.Fatalf("stale part poisoned the artifact: %d bytes", len(got))
	}
}

func TestFetchPayloadResumeKeepsPartOnTransportFailure(t *testing.T) {
	payload, m := payloadFixture(1000)
	aborted := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var start int64
		rng := r.Header.Get("Range")
		if rng != "" {
			if _, err := fmt.Sscanf(rng, "bytes=%d-", &start); err != nil {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			w.WriteHeader(http.StatusPartialContent)
		}
		// Serve exactly 4 bytes, then: the FIRST ranged request dies
		// mid-stream (the client must keep the part for the next
		// attempt); the follow-up serves the rest of the artifact.
		n := int64(4)
		if start+n > int64(len(payload)) {
			n = int64(len(payload)) - start
		}
		_, _ = w.Write(payload[start : start+n])
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		if rng != "" && !aborted {
			aborted = true
			panic(http.ErrAbortHandler)
		}
		_, _ = w.Write(payload[start+n:])
	}))
	defer server.Close()

	dir := tTempDir()
	f := testFetcher(server)
	f.TempDir = dir
	part := partPathFor(dir, m)
	if err := os.WriteFile(part, payload[:400], 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := f.FetchPayload(context.Background(), server.URL+"/central-dataset/gseer-dataset-manifest.json", m)
	if err == nil {
		t.Fatal("mid-stream abort must fail the attempt")
	}
	if _, statErr := os.Stat(part); os.IsNotExist(statErr) {
		t.Fatal("the part file must be kept after a transport failure (resume next time)")
	}

	// The next attempt resumes and succeeds.
	if _, err := f.FetchPayload(context.Background(), server.URL+"/central-dataset/gseer-dataset-manifest.json", m); err != nil {
		t.Fatalf("the follow-up resume must succeed, got %v", err)
	}
	if _, statErr := os.Stat(part); !os.IsNotExist(statErr) {
		t.Fatalf("the part file must be renamed away after success, stat err=%v", statErr)
	}
	got, _ := os.ReadFile(finalPathFor(dir, m))
	if string(got) != string(payload) {
		t.Fatalf("final payload mismatches after resume: %d bytes", len(got))
	}
}
