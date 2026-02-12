# propolis -- Development Guide for Claude Code

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

propolis is a Go library and runner binary for running OCI container images as
microVMs using libkrun. It provides a single-function-call API (`propolis.Run`)
that pulls an image, flattens layers, sets up networking, and boots a microVM.

**Module:** `github.com/stacklok/propolis`
**Go version:** 1.25.7
**License:** Apache 2.0

**Key characteristics:**
- **Two-process model**: Library (pure Go) spawns a CGO runner subprocess
- **CGO isolation**: Only `krun` package and `propolis-runner` binary need CGO
- **Functional options**: All configuration via `With*` option constructors
- **Extensible pipeline**: Hooks for rootfs modification, post-boot logic, custom networking, preflight checks
- **Content-addressable cache**: OCI images cached by manifest digest

## Build and Development Commands

All commands use [Task](https://taskfile.dev/) (`task --list` for full listing):

```bash
task build-dev         # Build runner for dev (requires system libkrun-devel, Linux only)
task build-dev-darwin  # Build runner on macOS (requires Homebrew libkrun, signs entitlements)
task build-dev-race    # Build runner with race detector
task test              # Run tests with race detector (go test -v -race ./...)
task test-coverage     # Run tests with coverage report (generates coverage.html)
task lint              # golangci-lint run ./...
task lint-fix          # Auto-fix lint issues
task fmt               # go fmt ./... + goimports -w .
task tidy              # go mod tidy
task verify            # fmt + lint + test (CI pipeline, runs in sequence)
task version           # Print version info from git tags
task clean             # Remove bin/ and coverage files
```

## Package Structure

| Package | CGO? | Description |
|---------|------|-------------|
| `propolis` (root) | No | Top-level API: `Run()`, `VM` type, functional options, hook types |
| `image` | No | OCI image pull via crane, layer flattening, rootfs extraction, `KrunConfig` |
| `krun` | **Yes** | CGO bindings to libkrun C API (context, VM config, `StartEnter`) |
| `net` | No | `Provider` interface and `Config`/`PortForward` types |
| `net/gvproxy` | No | Default `net.Provider` using gvproxy binary |
| `preflight` | No | `Checker` interface, `Check` struct, built-in KVM/HVF and port checks |
| `runner` | No | `Spawn()` / `Process` for managing the propolis-runner subprocess |
| `runner/cmd/propolis-runner` | **Yes** | The runner binary (calls `krun.StartEnter`, never returns) |
| `ssh` | No | ECDSA P-256 key generation and SSH client for guest communication |
| `state` | No | flock-based state persistence with atomic JSON writes |

## Code Patterns

### Error Handling

- Wrap errors with `fmt.Errorf("context: %w", err)`.
- Use descriptive context strings that form a readable chain (e.g.,
  `"pull image: parse image reference: ..."`)
- Return early on error; avoid nested if/else.

### Logging

- Use `log/slog` exclusively. No `fmt.Println` or `log.Printf` in library code.
- Use structured fields: `slog.Info("msg", "key", value)`.
- Debug level for internal operations, Info for lifecycle events, Warn/Error
  for failures.

### Extensible Interfaces

- `net.Provider` -- networking backend abstraction (Start, SocketPath, PID, Stop).
- `preflight.Checker` / `preflight.Check` -- pre-boot validation.
- `RootFSHook` and `PostBootHook` -- caller-provided functions.
- Functional options pattern (`Option` interface with `apply(*config)`).

### SPDX Headers

Every `.go` and `.yaml` file must start with:
```
// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0
```
(Use `#` comments for YAML files.)

## How to Add a New Preflight Check

1. Create a function that returns a `preflight.Check`:

```go
// In preflight/mycheck.go
func MyCheck() Check {
    return Check{
        Name:        "mycheck",
        Description: "Verify something important",
        Run: func(ctx context.Context) error {
            // Return nil on success, descriptive error on failure.
            // Include remediation hints in the error message.
            return nil
        },
        Required: true, // false makes it advisory (logged as warning)
    }
}
```

2. Register it from the caller via options:

```go
propolis.Run(ctx, imageRef,
    propolis.WithPreflightChecks(preflight.MyCheck()),
)
```

Or add it to `registerPlatformChecks()` in the appropriate build-tagged file
(`preflight/kvm_linux.go` or `preflight/hvf_darwin.go`) if it should run by
default on that platform.

3. Platform-specific checks use build tags (`//go:build linux` or
   `//go:build darwin`). Put each platform's implementation in a separate file.

## How to Add a New Network Provider

1. Implement the `net.Provider` interface:

```go
// In net/myprovider/provider.go
package myprovider

import (
    "context"
    "github.com/stacklok/propolis/net"
)

type Provider struct {
    sockPath string
    pid      int
}

func New() *Provider {
    return &Provider{}
}

func (p *Provider) Start(ctx context.Context, cfg net.Config) error {
    // Launch the networking process.
    // Block until the Unix socket is ready to accept connections.
    // cfg.LogDir is where to write logs.
    // cfg.Forwards contains port forwarding rules.
    return nil
}

func (p *Provider) SocketPath() string {
    // Return the Unix socket path for virtio-net.
    // The runner passes this to krun_add_net_unixstream.
    return p.sockPath
}

func (p *Provider) PID() int {
    return p.pid
}

func (p *Provider) Stop() {
    // Terminate the process and clean up socket files.
}
```

2. `Start` must block until the provider is ready. `SocketPath` returns the
   Unix socket path. The socket must use SOCK_STREAM with 4-byte big-endian
   length-prefixed Ethernet frames (the QEMU transport protocol).

3. Use it:

```go
propolis.Run(ctx, imageRef,
    propolis.WithNetProvider(myprovider.New()),
)
```

## How to Add a New Rootfs Hook

Rootfs hooks modify the extracted filesystem before `.krun_config.json` is
written and before the VM boots. They receive the rootfs path and the parsed
OCI image configuration.

```go
// Define the hook function.
func installSSHKeys(keyDir string) propolis.RootFSHook {
    return func(rootfsPath string, cfg *image.OCIConfig) error {
        sshDir := filepath.Join(rootfsPath, "root", ".ssh")
        if err := os.MkdirAll(sshDir, 0o700); err != nil {
            return fmt.Errorf("create .ssh dir: %w", err)
        }
        pubKey, err := os.ReadFile(filepath.Join(keyDir, "id_ecdsa.pub"))
        if err != nil {
            return fmt.Errorf("read public key: %w", err)
        }
        return os.WriteFile(
            filepath.Join(sshDir, "authorized_keys"),
            pubKey, 0o600,
        )
    }
}

// Register it.
propolis.Run(ctx, imageRef,
    propolis.WithRootFSHook(installSSHKeys("/path/to/keys")),
)
```

Multiple hooks run in registration order. If any hook returns an error, the
pipeline aborts.

## Testing Approach

- Library packages (everything except `krun` and `runner/cmd/propolis-runner`)
  are tested with `CGO_ENABLED=0`.
- The `krun` package requires `CGO_ENABLED=1` and `libkrun-devel` installed.
- Use `go vet` with exclusions for krun/runner to validate pure-Go packages:
  `CGO_ENABLED=0 go vet $(go list ./... | grep -v krun | grep -v propolis-runner)`
- Prefer table-driven tests.
- Test files go alongside the code they test (same package).
- Run `task test` for the full test suite with race detector.
- Run `task test-coverage` to generate coverage.html.

## Important Files

| File | Purpose |
|------|---------|
| `propolis.go` | `Run()` entry point, orchestrates the full pipeline (7 steps) |
| `vm.go` | `VM` type with `Stop`, `Status`, `Remove`, accessor methods |
| `options.go` | All `With*` option constructors, `config` struct, `defaultConfig()` |
| `runner/spawn.go` | `Spawn()` starts propolis-runner as detached subprocess (setsid) |
| `runner/config.go` | `Config` struct serialized as JSON to the runner binary |
| `runner/cmd/propolis-runner/main.go` | Runner binary entry point, calls krun APIs |
| `krun/context.go` | CGO bindings to all libkrun C functions |
| `krun/doc.go` | Package documentation for krun |
| `image/pull.go` | `Pull()`, layer flattening, rootfs extraction with security checks |
| `image/config.go` | `OCIConfig`, `KrunConfig`, `.krun_config.json` writer |
| `image/cache.go` | Content-addressable rootfs cache by digest |
| `net/provider.go` | `Provider` interface definition |
| `net/gvproxy/provider.go` | gvproxy implementation of `net.Provider` (YAML config, socket wait) |
| `preflight/checker.go` | `Checker` interface, default implementation, `RunAll` logic |
| `preflight/kvm_linux.go` | KVM device check (character device, permissions, open test) |
| `preflight/hvf_darwin.go` | macOS platform checks (no-op, HVF assumed available) |
| `preflight/ports.go` | Port availability check with `ss` process info lookup |
| `preflight/resources_linux.go` | Disk space and CPU/RAM checks (Linux, advisory) |
| `preflight/resources_darwin.go` | Disk space and resource checks (macOS, no-op stubs) |
| `state/state.go` | `Manager`, `LockedState`, atomic JSON persistence with flock |
| `ssh/client.go` | SSH client: Run, RunSudo, RunStream, CopyTo, CopyFrom, WaitForReady |
| `ssh/keygen.go` | ECDSA P-256 key pair generation |
| `Taskfile.yaml` | All build, test, lint, and clean tasks |

## Two-Process Model

The library (your app) never links libkrun. It spawns `propolis-runner` as a
subprocess, passing `runner.Config` as JSON in `argv[1]`. The runner calls
`krun_start_enter()` which takes over the process and never returns. The
library monitors the runner PID and manages its lifecycle via signals.

Why two processes:
- `krun_start_enter()` calls `exit()` when the guest shuts down -- it never
  returns to the caller.
- If called directly from a Go application, the entire Go runtime would be lost.
- The runner is intentionally minimal: it validates config, creates a libkrun
  context, configures the VM, and calls StartEnter. All orchestration lives in
  the library.

## Common Development Tasks

### Adding a New Option

1. Add the field to the `config` struct in `options.go`.
2. Set the default value in `defaultConfig()` if needed.
3. Create a `With*` option constructor function following the existing pattern:
   ```go
   func WithMyOption(value string) Option {
       return optionFunc(func(c *config) { c.myField = value })
   }
   ```
4. Use the field in `propolis.go` (in `Run()`) where appropriate.
5. If the option affects the runner, add the field to `runner.Config` in
   `runner/config.go` and handle it in `runner/cmd/propolis-runner/main.go`.

### Adding a New Package

1. Create the package directory under the project root.
2. Add a `doc.go` file with the SPDX header and package documentation.
3. Ensure the package does not import `krun` (to keep it CGO-free) unless it
   is intentionally a CGO package.
4. Add it to the package structure table in `CLAUDE.md` and `README.md`.

### Adding a New File

Every new `.go` file must include the SPDX header as the first two lines:
```go
// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0
```

### Modifying the Runner Config

The `runner.Config` struct in `runner/config.go` is serialized as JSON and
passed to the runner binary. The runner has its own duplicate `Config` struct
in `runner/cmd/propolis-runner/main.go`. When adding a field:
1. Add it to `runner.Config` with the appropriate JSON tag.
2. Add it to the runner's `Config` struct with the same JSON tag.
3. Handle the new field in `runVM()` in the runner's `main.go`.

## Troubleshooting

### VM Fails to Start

```bash
# Check KVM availability
ls -la /dev/kvm

# Check console output for guest-side errors
cat ~/.config/propolis/console.log

# Check runner stderr for host-side errors
cat ~/.config/propolis/vm.log

# Check gvproxy logs
cat ~/.config/propolis/gvproxy.log

# Verify the runner binary exists
which propolis-runner
```

### Tests Fail with CGO Errors

If tests fail because of CGO/libkrun dependencies, exclude the krun package:
```bash
CGO_ENABLED=0 go test $(go list ./... | grep -v krun | grep -v propolis-runner)
```

### Port Conflicts

```bash
ss -tlnp | grep ':8080'
```

## Commit Guidelines

Follow conventional commit format:
- Limit subject line to 50 characters
- Use imperative mood, capitalize, no trailing period
- Separate subject from body with blank line

Never do `git add -A`.

## Additional Documentation

| Document | Purpose |
|----------|---------|
| [README.md](README.md) | User-facing documentation, quick start, prerequisites |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Deep technical architecture, security model, internals |
| [docs/MACOS.md](docs/MACOS.md) | macOS support, code signing, Hypervisor.framework |
| [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Common issues, log files, resource limits, licensing |
