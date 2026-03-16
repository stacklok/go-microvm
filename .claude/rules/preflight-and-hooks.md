---
paths:
  - "preflight/**"
  - "net/**"
---

# Preflight Checks and Extension Points

## Adding a Preflight Check
- Create a function returning `preflight.Check` with Name, Description, Run, and Required fields
- See existing checks in `preflight/kvm_linux.go` and `preflight/ports.go` for patterns
- Platform-specific checks go in build-tagged files (`//go:build linux` or `//go:build darwin`)
- Register via `microvm.WithPreflightChecks()` or add to `registerPlatformChecks()` for defaults

## Adding a Network Provider
- Implement the `net.Provider` interface (Start, SocketPath, Stop)
- `Start` must block until the Unix socket is ready to accept connections
- Socket must use SOCK_STREAM with 4-byte big-endian length-prefixed Ethernet frames (QEMU transport protocol)
- See `net/hosted/provider.go` for the reference implementation

## Rootfs Hooks
- Type: `func(rootfsPath string, cfg *image.OCIConfig) error`
- Run before `.krun_config.json` is written and before VM boot
- Multiple hooks run in registration order; any error aborts the pipeline
- Register via `microvm.WithRootFSHook()`
