# propolis -- Development Guide for Claude Code

## Project overview

propolis is a Go library and runner binary for running OCI container images as
microVMs using libkrun. The library packages are pure Go (no CGO). The `krun`
package and the `propolis-runner` binary require CGO and libkrun-devel.

Module: `github.com/stacklok/propolis`, Go 1.25.7.

## Build commands

```bash
task build-dev         # Build runner for dev (requires system libkrun-devel)
task build-dev-darwin  # Build runner on macOS (requires Homebrew libkrun)
task build-dev-race    # Build runner with race detector
task test              # Run tests with race detector
task test-coverage     # Run tests with coverage report
task lint              # golangci-lint
task lint-fix          # Auto-fix lint issues
task fmt               # go fmt + goimports
task tidy              # go mod tidy
task verify            # fmt + lint + test (CI pipeline)
task version           # Print version info from git
task clean             # Remove bin/ and coverage files
```

## Package structure

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
| `ssh` | No | ECDSA key generation and SSH client for guest communication |
| `state` | No | flock-based state persistence with atomic JSON writes |

## Code patterns

### Error handling
- Wrap errors with `fmt.Errorf("context: %w", err)`.
- Use descriptive context strings that form a readable chain (e.g.,
  `"pull image: parse image reference: ..."`)
- Return early on error; avoid nested if/else.

### Logging
- Use `log/slog` exclusively. No `fmt.Println` or `log.Printf`.
- Use structured fields: `slog.Info("msg", "key", value)`.
- Debug level for internal operations, Info for lifecycle events, Warn/Error
  for failures.

### Extensible interfaces
- `net.Provider` -- networking backend abstraction.
- `preflight.Checker` / `preflight.Check` -- pre-boot validation.
- `RootFSHook` and `PostBootHook` -- caller-provided functions.
- Functional options pattern (`Option` interface with `apply(*config)`).

### SPDX headers
Every `.go` and `.yaml` file must start with:
```
// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0
```
(Use `#` comments for YAML files.)

## How to add a new preflight check

1. Create a function that returns a `preflight.Check`:

```go
// In preflight/mycheck.go
func MyCheck() Check {
    return Check{
        Name:        "mycheck",
        Description: "Verify something important",
        Run: func(ctx context.Context) error {
            // Return nil on success, descriptive error on failure.
            return nil
        },
        Required: true, // false for warnings
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
if it should run by default.

## How to add a new network provider

1. Implement the `net.Provider` interface:

```go
type Provider interface {
    Start(ctx context.Context, cfg Config) error
    SocketPath() string
    PID() int
    Stop()
}
```

2. `Start` must block until the provider is ready. `SocketPath` returns the
   Unix socket path for virtio-net. `Stop` terminates the provider process.

3. Use it:

```go
propolis.Run(ctx, imageRef,
    propolis.WithNetProvider(myprovider.New()),
)
```

## Testing approach

- Library packages (everything except `krun` and `runner/cmd/propolis-runner`)
  are tested with `CGO_ENABLED=0`.
- The `krun` package requires `CGO_ENABLED=1` and `libkrun-devel` installed.
- Use `go vet` with exclusions for krun/runner to validate pure-Go packages:
  `CGO_ENABLED=0 go vet $(go list ./... | grep -v krun | grep -v propolis-runner)`
- Prefer table-driven tests.
- Test files go alongside the code they test (same package).

## Important files

| File | Purpose |
|------|---------|
| `propolis.go` | `Run()` entry point, orchestrates the full pipeline |
| `vm.go` | `VM` type with `Stop`, `Status`, `Remove` |
| `options.go` | All `With*` option constructors, `config` struct, defaults |
| `runner/spawn.go` | `Spawn()` starts propolis-runner as detached subprocess |
| `runner/config.go` | `Config` struct serialized as JSON to the runner binary |
| `runner/cmd/propolis-runner/main.go` | Runner binary entry point, calls krun APIs |
| `krun/context.go` | CGO bindings to all libkrun C functions |
| `image/pull.go` | `Pull()`, layer flattening, rootfs extraction |
| `image/config.go` | `OCIConfig`, `KrunConfig`, `.krun_config.json` writer |
| `image/cache.go` | Content-addressable rootfs cache by digest |
| `net/provider.go` | `Provider` interface definition |
| `net/gvproxy/provider.go` | gvproxy implementation of `net.Provider` |
| `preflight/checker.go` | `Checker` interface and default implementation |
| `state/state.go` | `Manager`, `LockedState`, atomic JSON persistence |
| `ssh/client.go` | SSH client with `Run`, `CopyTo`, `WaitForReady` |
| `ssh/keygen.go` | ECDSA P-256 key pair generation |

## Two-process model

The library (your app) never links libkrun. It spawns `propolis-runner` as a
subprocess, passing `runner.Config` as JSON in argv[1]. The runner calls
`krun_start_enter()` which takes over the process and never returns. The
library monitors the runner PID and manages its lifecycle via signals.

Never do `git add -A`.
