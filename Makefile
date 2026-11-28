# GSEER — internet-asset search engine.
# Copyright (C) 2026  The GSEER Authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# GSEER Makefile — v0.3.1.
#
# Targets required by M1 (Phase 1 plan §3 M1):
#   build  — compile the gseer binary with version ldflags
#   test   — go test ./...
#   vet    — go vet ./...
#   lint   — golangci-lint run
#   fuzz   — go test -fuzz (no fuzz targets until M5; target is a stub)
#
# The build target injects version/commit/built_at via -ldflags so that
# `gseer version` reports substantiated values rather than "dev".  An
# un-injected binary (e.g. `go run`) honestly reports "dev"/"unknown".

MODULE   := github.com/Lutfifakee-Project/gseer
BIN      := gseer
GOFLAGS  := -trimpath
# LDFLAGS is RECURSIVELY expanded (=) so that $(VERSION)/$(COMMIT)/$(BUILT_AT)
# are resolved at build time — after the `?=` defaults below.  An immediate
# expansion (:=) here would freeze them empty and a plain `make build` would
# ship a binary whose version string is "" instead of the honest "dev".
LDFLAGS  = -X $(MODULE)/internal/version.Version=$(VERSION) \
	    -X $(MODULE)/internal/version.Commit=$(COMMIT) \
	    -X $(MODULE)/internal/version.BuiltAt=$(BUILT_AT)

# Default version metadata: honest defaults rather than fabricated values.
# CI overrides VERSION/COMMIT/BUILT_AT via the environment; COMMIT/BUILT_AT
# left empty print "unknown" (honest).  VERSION defaults to the official
# release identity below, so a plain `make build` stamps it (CI may still
# override).
VERSION  ?= v0.3.3-rc2
COMMIT   ?=
BUILT_AT ?=

# Tooling.  golangci-lint and govulncheck are expected on PATH (CI installs
# them; local devs run `make tools` once).
GOLANGCI_LINT := golangci-lint
GOVULNCHECK   := govulncheck

.PHONY: all build test vet lint fuzz vuln tools clean tidy fmt check \
	bench-corpus bench-baseline bench-check release-validate

all: build

## build: compile the gseer binary into ./bin/gseer
build:
	@mkdir -p bin
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/gseer

## run: build and run with any args (e.g. `make run ARGS=version`)
run: build
	./bin/$(BIN) $(ARGS)

## test: run all unit + integration tests (excluding -short-skipped ones)
test:
	go test ./...

## test-short: run only tests that don't require external tooling
test-short:
	go test -short ./...

## vet: go vet ./...
vet:
	go vet ./...

## lint: golangci-lint run
lint:
	$(GOLANGCI_LINT) run

## fuzz: run fuzz targets (none until M5; stub target for CI wiring)
fuzz:
	@echo "fuzz targets land in M5 (lexer) and M6 (parser); this stub keeps the CI target green until then."

## vuln: govulncheck ./...
vuln:
	$(GOVULNCHECK) ./...

## tools: install golangci-lint + govulncheck into $$GOPATH/bin
tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest

## tidy: go mod tidy
tidy:
	go mod tidy

## fmt: go fmt ./...
fmt:
	go fmt ./...

## check: the local pre-push gate (build + vet + lint + test + vuln)
check: build vet lint test vuln
	@echo "M1 verification complete."

# --- R140 performance regression gate --------------------------------------
# The gate measures the fixed workload set through the production search
# service (docs/BENCHMARKING.md).  Every knob is a make variable for dev
# workflows, but `make release-validate` CANNOT skip bench-check: with no
# baseline it exits 2 (E_NO_BASELINE), never silently passes.
BENCH_HOME        ?= $(HOME)/.gseer-bench
BENCH_DB          := $(BENCH_HOME)/gseer.db
BENCH_ASSETS      ?= 200000
BENCH_RUNS        ?= 5
BENCH_TOLERANCE   ?= 1.2
BENCH_MIN_ABS_MS  ?= 25

## bench-corpus: create the documented bench corpus (benchgen; skipped if present)
bench-corpus:
	@mkdir -p $(BENCH_HOME)
	@if [ -f "$(BENCH_DB)" ]; then \
		echo "bench corpus exists: $(BENCH_DB) (delete it to regenerate)"; \
	else \
		go run ./internal/bench/benchgen -db $(BENCH_DB) -assets $(BENCH_ASSETS); \
	fi

## bench-baseline: measure and save the performance baseline (bench-corpus first)
bench-baseline: build bench-corpus
	GSEER_HOME=$(BENCH_HOME) ./bin/$(BIN) bench run --runs $(BENCH_RUNS) --save

## bench-check: fresh measurement + regression gate vs baseline (exit 6 blocks)
bench-check: build bench-corpus
	@if [ ! -f "$(BENCH_HOME)/bench/baseline.json" ]; then \
		echo "E_NO_BASELINE: no baseline in $(BENCH_HOME)/bench — the gate cannot be skipped."; \
		echo "Next: make bench-baseline (one-time, ~minutes)"; \
		exit 2; \
	fi
	GSEER_HOME=$(BENCH_HOME) ./bin/$(BIN) bench run --runs $(BENCH_RUNS)
	GSEER_HOME=$(BENCH_HOME) ./bin/$(BIN) bench compare --tolerance $(BENCH_TOLERANCE) --min-abs-ms $(BENCH_MIN_ABS_MS)

## release-validate: full pre-release gate — build + vet + test + bench gate
release-validate: build vet test bench-check
	@echo "Release validation complete (incl. R140 performance gate)."

## clean: remove build artifacts
clean:
	rm -rf bin

## help: this listing
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //; s/:.*\t/: /' | column -t -s ':'
