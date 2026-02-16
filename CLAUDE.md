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

- `propolis.go` -- Entry point: `Run()` orchestrates the pipeline (preflight, pull, hooks, config, net, spawn, post-boot)
- `options.go` -- All `With*` option constructors, `config` struct, `defaultConfig()`
- `vm.go` -- `VM` type returned by `Run()` with `Stop`, `Status`, `Remove`
- `image/` -- OCI pull via `ImageFetcher` interface (daemon then remote fallback), layer flattening, content-addressable cache
- `runner/` -- `Spawner`/`ProcessHandle` interfaces, launches detached propolis-runner subprocess via setsid
- `runner/cmd/propolis-runner/` -- CGO binary: calls `krun.StartEnter`, never returns; creates in-process VirtualNetwork by default
- `krun/` -- CGO bindings to libkrun C API
- `net/` -- `Provider` interface for custom networking backends
- `net/firewall/` -- Frame-level packet filtering, connection tracking, relay
- `net/hosted/` -- Hosted `net.Provider` running VirtualNetwork in caller's process with HTTP services on gateway IP
- `net/topology/` -- Shared network topology constants (subnet, gateway, guest IP, MTU)
- `preflight/` -- `Checker` interface, platform-specific checks via build tags
- `ssh/` -- ECDSA P-256 keygen and SSH client for guest communication
- `state/` -- flock-based atomic JSON state persistence

## Things That Will Bite You

- **CGO boundary is strict**: Only `krun/` and `runner/cmd/propolis-runner/` use CGO. Every other package MUST stay `CGO_ENABLED=0`. Never import `krun` from a non-CGO package.
- **Runner config is duplicated**: `runner.Config` in `runner/config.go` and a duplicate `Config` struct in `runner/cmd/propolis-runner/main.go`. When adding a field, update BOTH structs with the same JSON tag, then handle it in `runVM()`.
- **`krun_start_enter()` never returns**: It calls `exit()` when the guest shuts down. That's why we need the two-process model -- the runner process is sacrificial.
- **Platform build tags**: Preflight checks, resource checks, and some net code use `//go:build linux` or `//go:build darwin`. Each platform goes in a separate file.
- **Tests excluding CGO packages**: When CGO isn't available, exclude krun: `CGO_ENABLED=0 go test $(go list ./... | grep -v krun | grep -v propolis-runner)`
- **Functional options pattern**: All public config uses `With*` constructors applying to unexported `config` struct via `optionFunc`. Follow the existing pattern in `options.go` exactly.

## Conventions

- **SPDX headers required**: Every `.go` and `.yaml` file starts with:
  ```
  // SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
  // SPDX-License-Identifier: Apache-2.0
  ```
  Use `#` comments for YAML files.
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

- @docs/ARCHITECTURE.md -- Deep technical architecture
- @docs/SECURITY.md -- Trust boundaries, guest escape analysis, hardening
- @docs/NETWORKING.md -- Networking modes (runner-side, hosted), firewall, wire protocol
- @docs/MACOS.md -- macOS support, code signing, Hypervisor.framework
- @docs/TROUBLESHOOTING.md -- Common issues, log files, resource limits
