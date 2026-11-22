// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// dataset_fetcher_trust_test.go — plumbing contract for the fetcher the
// CLI builds from config (the dataset.trusted_redirect_hosts seam): an
// UNSET list keeps the product defaults (the official GitHub release-asset
// CDN the channel redirects to), a configured list replaces the defaults
// verbatim, and an explicitly empty list trusts nothing.

import (
	"reflect"
	"strings"
	"testing"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/dataset"
)

// TestDatasetFetcherFromConfigTrustDefaults — nil config and an unset
// trusted_redirect_hosts list both leave the fetcher on the product
// defaults, so `gseer setup`, `gseer dataset update`, and the freshness
// check follow the official channel's CDN hop out of the box.
func TestDatasetFetcherFromConfigTrustDefaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{
		{"nil config", nil},
		{"unset list", &config.Config{}},
		{"personal profile, dataset unset", &config.Config{Profile: config.ProfilePersonal}},
	} {
		f := datasetFetcherFromConfig(tc.cfg)
		want := append([]string(nil), dataset.DefaultTrustedRedirectHosts...)
		if !reflect.DeepEqual(f.TrustedRedirectHosts, want) {
			t.Errorf("%s: fetcher must keep the default trusted hosts (want %v, got %v)",
				tc.name, want, f.TrustedRedirectHosts)
		}
	}
}

// TestDatasetFetcherFromConfigListOverrides — a configured list replaces
// the defaults verbatim (exact list, order included); an explicitly
// empty list trusts nothing (strict fail-closed choice).
func TestDatasetFetcherFromConfigListOverrides(t *testing.T) {
	cfg := &config.Config{}
	cfg.Dataset.TrustedRedirectHosts = []string{"cdn.owner.example", "mirror.owner.example"}
	f := datasetFetcherFromConfig(cfg)
	want := []string{"cdn.owner.example", "mirror.owner.example"}
	if !reflect.DeepEqual(f.TrustedRedirectHosts, want) {
		t.Errorf("a configured list must replace the defaults verbatim (want %v, got %v)", want, f.TrustedRedirectHosts)
	}
	for _, h := range dataset.DefaultTrustedRedirectHosts {
		for _, got := range f.TrustedRedirectHosts {
			if strings.EqualFold(got, h) {
				t.Errorf("the GitHub CDN %q must not stay trusted once the operator configures a list", h)
			}
		}
	}

	cfg.Dataset.TrustedRedirectHosts = []string{}
	if got := datasetFetcherFromConfig(cfg).TrustedRedirectHosts; len(got) != 0 || got == nil {
		t.Errorf("an explicit empty list must reach the fetcher as an empty (non-nil) list, got %#v", got)
	}
}
