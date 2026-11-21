// GSEER — internet-asset search engine.
// Copyright (c) 2026 Lutfifakee Project
//
// SPDX-License-Identifier: MIT
// This file is part of GSEER and is licensed under the MIT License — see LICENSE.

package cli

// observe_store.go — the profile-aware opener for `gseer scope` /
// `gseer scan` (v0.3.2).  Mirrors registry.go:
//
//   - personal     → sqlite.Store (one embedded file, no server);
//   - self-hosted  → postgres.Store (the hardened deployment).

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/Lutfifakee-Project/gseer/internal/config"
	"github.com/Lutfifakee-Project/gseer/internal/storage/postgres"
	"github.com/Lutfifakee-Project/gseer/internal/storage/sqlite"
)

// Compile-time proof that BOTH engines satisfy the full active-
// observation contract — a signature drift on either side fails the
// build here, not at an operator's terminal.
var (
	_ observeBackend = (*postgres.Store)(nil)
	_ observeBackend = (*sqlite.Store)(nil)
)

// openObserveStore loads the config, resolves the profile, and opens
// the scope/scan store for whichever engine that profile selects.  The
// returned closer releases the engine's resources and is always
// non-nil when err == nil.
func openObserveStore(cmd *cobra.Command) (observeBackend, func(), error) {
	cfg, cerr := engineConfigOrInit(cmd)
	if cerr != nil {
		return nil, nil, fmt.Errorf("%s\nTry: gseer setup --help", cerr.Error())
	}
	switch cfg.Profile {
	case config.ProfilePersonal:
		st, res, err := personalStore(commandContext(cmd), cfg)
		if err != nil {
			return nil, nil, err
		}
		return st, func() { _ = res.DB.Close() }, nil
	case config.ProfileSelfHosted:
		pool, err := openAppPool(cmd, cfg)
		if err != nil {
			return nil, nil, err
		}
		return postgres.NewStore(pool), func() { pool.Close() }, nil
	default:
		return nil, nil, fmt.Errorf("E_CONFIG: `gseer scope` and `gseer scan` manage the LOCAL registry\n"+
			"Why: the current profile (%s) has no local engine (validation should have rejected it)\n"+
			"Try: gseer setup  (single-file personal mode) or gseer setup --self-hosted", cfg.Profile)
	}
}
