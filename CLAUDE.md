# propolis

Go library + runner binary for running OCI container images as microVMs via libkrun.
Two-process model: pure-Go library spawns a CGO runner subprocess. Module: `github.com/stacklok/propolis`.

## Commands

```bash
task build-dev          # Build runner (requires libkrun-devel, Linux)
task build-dev-darwin   # Build runner (macOS, signs entitlements)
task test               # go test -v -race ./...
task lint               # golangci-lint run ./...
task lint-fix           # Auto-fix lint issues
task fmt                # go fmt + goimports
task verify             # fmt + lint + test (CI pipeline)
task tidy               # go mod tidy
task clean              # Remove bin/ and coverage files
```

Run a single test: `go test -v -race -run TestName ./path/to/package`

## Architecture

Entry point: `propolis.go:Run()` orchestrates the full pipeline (preflight, pull, hooks, config, net, spawn, post-boot). Config via functional options in `options.go`. Returns a `*VM` handle (`vm.go`).

**CGO boundary**: Only `krun/` and `runner/cmd/propolis-runner/` use CGO. Everything else is pure Go. The runner binary is sacrificial -- `krun_start_enter()` never returns, so it runs in a detached subprocess.

**Key subsystems**: `image/` (OCI pull + cache), `runner/` (subprocess spawning), `net/` (Provider interface + firewall + hosted mode + topology constants), `preflight/` (platform checks via build tags), `ssh/` (keygen + client), `state/` (flock-based JSON persistence), `internal/` (procutil, version).

## Things That Will Bite You

- **CGO boundary is strict**: Only `krun/` and `runner/cmd/propolis-runner/` use CGO. Every other package MUST stay `CGO_ENABLED=0`. Never import `krun` from a non-CGO package.
- **Runner config is duplicated**: `runner.Config` in `runner/config.go` and a duplicate `Config` struct in `runner/cmd/propolis-runner/main.go`. When adding a field, update BOTH structs with the same JSON tag, then handle it in `runVM()`.
- **`krun_start_enter()` never returns**: It calls `exit()` when the guest shuts down. That's why we need the two-process model -- the runner process is sacrificial.
- **Platform build tags**: Preflight checks, resource checks, and some net code use `//go:build linux` or `//go:build darwin`. Each platform goes in a separate file.
- **Tests excluding CGO packages**: When CGO isn't available, exclude krun: `CGO_ENABLED=0 go test $(go list ./... | grep -v krun | grep -v propolis-runner)`
- **Functional options pattern**: All public config uses `With*` constructors applying to unexported `config` struct via `optionFunc`. Follow the existing pattern in `options.go` exactly.

## Conventions

- **SPDX headers required**: Every `.go` and `.yaml` file needs `// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.` and `// SPDX-License-Identifier: Apache-2.0` (use `#` for YAML).
- Use `log/slog` exclusively -- no `fmt.Println` or `log.Printf` in library code.
- Wrap errors with `fmt.Errorf("context: %w", err)` forming readable chains.
- Prefer table-driven tests. Test files go alongside the code they test.
- When adding a new package, include a `doc.go` with SPDX header and ensure it doesn't import `krun`.

## Commit Guidelines

- Imperative mood, capitalize, no trailing period, limit subject to 50 chars
- IMPORTANT: Never use `git add -A`. Stage specific files only.

## Verification

After any code change:
```bash
task fmt && task lint    # Format and lint
task test                # Full test suite with race detector
```

After modifying CGO-free packages only:
```bash
CGO_ENABLED=0 go vet $(go list ./... | grep -v krun | grep -v propolis-runner)
```

When tests fail, fix the implementation, not the tests.

## Reference Docs

Read these on demand when working on related subsystems:
- `docs/ARCHITECTURE.md` -- Deep technical architecture, two-process model, extension points
- `docs/SECURITY.md` -- Trust boundaries, guest escape analysis, hardening
- `docs/NETWORKING.md` -- Networking modes (runner-side, hosted), firewall, wire protocol
- `docs/MACOS.md` -- macOS support, code signing, Hypervisor.framework
- `docs/TROUBLESHOOTING.md` -- Common issues, log files, resource limits
