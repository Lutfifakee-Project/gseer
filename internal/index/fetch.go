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

package index

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// fetch.go — the HTTP fetcher for the manifest and the snapshot
// (mirrors internal/update's Fetcher: hard size cap, timeout, refuses
// non-HTTP(S) schemes, redacts credential-looking URLs in errors).

// MaxSnapshotBytes caps a snapshot download (512 MiB is generous for a
// personal-scale index and refuses memory-bomb URLs).
const MaxSnapshotBytes = 512 << 20

// MaxManifestBytes caps the signed manifest (a small JSON document).
const MaxManifestBytes = 1 << 20

// Fetcher downloads a URL with a hard cap.  The zero value uses a
// client with a 5-minute timeout.
type Fetcher struct {
	Client *http.Client
}

// Fetch reads the whole body (≤ cap bytes) from rawURL.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string, capBytes int64) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, &Error{
			Code: CodeURL,
			What: "the index URL is not HTTP(S)",
			Why:  redactURL(rawURL),
			Next: "the manifest is broken or the config is wrong; fetch the official channel",
		}
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, &Error{Code: CodeURL, What: "cannot build the request", Why: redactURL(rawURL)}
	}
	req.Header.Set("User-Agent", "gseer-index/1 (shared-index protocol v1)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, errf(CodeUnreachable, "the index endpoint did not answer",
			err.Error()+" ("+redactURL(rawURL)+")",
			"check network connectivity; retry later", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, &Error{
			Code: CodeHTTP,
			What: fmt.Sprintf("the index endpoint returned HTTP %d", resp.StatusCode),
			Why:  redactURL(rawURL),
			Next: "the release channel may be down, the sequence not yet published, or the URL stale",
		}
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, capBytes+1))
	if err != nil {
		return nil, errf(CodeHTTP, "reading the index payload failed", err.Error(), "retry later", err)
	}
	if int64(len(payload)) > capBytes {
		return nil, &Error{Code: CodeSize, What: "the index payload exceeds the size cap",
			Next: "refuse; a legitimate snapshot fits the cap"}
	}
	return payload, nil
}

// redactURL strips any userinfo from a URL before it lands in an error
// message (the httpx pattern — URLs are operator-controlled values).
func redactURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	u.User = url.User("REDACTED")
	return u.String()
}
