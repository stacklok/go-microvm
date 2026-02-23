# macOS Support

propolis supports macOS on Apple Silicon (arm64) using Hypervisor.framework.

## Requirements

- **Apple Silicon** (M1/M2/M3/M4) -- Intel Macs are not supported
- **macOS 11+** -- Hypervisor.framework requires Big Sur or later
- **libkrun** and **libkrunfw** -- install via Homebrew (see below) or build from source

## Installing libkrun

The easiest way to install libkrun on macOS is via Homebrew:

```bash
brew tap slp/krun
brew install libkrun libkrunfw
```

This installs the libraries and headers into Homebrew's prefix (`/opt/homebrew`
on Apple Silicon, `/usr/local` on Intel). The CGO directives in propolis
automatically search both paths.

## Key Platform Differences

| Aspect | Linux | macOS |
|--------|-------|-------|
| Hypervisor | KVM (`/dev/kvm`) | Hypervisor.framework |
| Shared libraries | `.so` (libkrun.so.1, libkrunfw.so.5) | `.dylib` (libkrun.dylib, libkrunfw.dylib) |
| Library path env | `LD_LIBRARY_PATH` | `DYLD_LIBRARY_PATH` |
| Code signing | Not required | Required (hypervisor entitlement) |
| PID identity check | `/proc/<pid>/exe` readlink | `signal(0)` best-effort |

## Code Signing

macOS requires binaries that use Hypervisor.framework to be signed with
specific entitlements. Without these, the process will crash with
`EXC_BAD_ACCESS` when trying to create a VM context.

Two entitlements are required (see `assets/entitlements.plist`):

- `com.apple.security.hypervisor` -- access to Hypervisor.framework
- `com.apple.security.cs.disable-library-validation` -- allows loading
  libkrun from non-system paths (e.g., Homebrew)

The propolis-runner binary must be signed:

```bash
codesign --entitlements assets/entitlements.plist --force -s - bin/propolis-runner
```

The `task build-dev-darwin` command handles signing automatically.

## DYLD_LIBRARY_PATH

When using bundled (non-system) libraries, the runner subprocess needs
`DYLD_LIBRARY_PATH` set. propolis handles this automatically via
`libkrun.WithLibDir()` (passed to `libkrun.NewBackend()`). macOS SIP (System Integrity Protection) strips
`DYLD_LIBRARY_PATH` from child processes in some contexts -- if the runner
fails to find libkrun, ensure SIP isn't interfering.

## Troubleshooting

### Hypervisor.framework not available

```bash
sysctl kern.hv_support
# Should return: kern.hv_support: 1
```

If 0, Hypervisor.framework is not available (Intel Mac or VM without
nested virtualization).

### Code signing errors

```
EXC_BAD_ACCESS (code=1, address=0x0)
```

The propolis-runner binary is not signed with the hypervisor entitlement.
Re-sign it:

```bash
codesign --entitlements assets/entitlements.plist --force -s - bin/propolis-runner
```

### DYLD_LIBRARY_PATH issues

```
dyld: Library not loaded: @rpath/libkrun.dylib
```

The runner can't find libkrun. Set `libkrun.WithLibDir()` (via
`libkrun.NewBackend()`) to the directory containing `libkrun.dylib` and
`libkrunfw.dylib`.
