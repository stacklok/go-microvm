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
| Shared libraries | `.so` (libkrun.so.1, libkrunfw.so.5) | `.dylib` (libkrun.1.dylib, libkrunfw.5.dylib) |
| Library path env | `LD_LIBRARY_PATH` | `DYLD_LIBRARY_PATH` |
| Code signing | Not required | Required (hypervisor entitlement) |
| PID identity check | `/proc/<pid>/exe` readlink | `signal(0)` best-effort |

## Code Signing

macOS requires binaries that use Hypervisor.framework to be signed with
specific entitlements. Without these, the process will crash with
`EXC_BAD_ACCESS` when trying to create a VM context.

Three entitlements are required (see `assets/entitlements.plist`):

- `com.apple.security.hypervisor` -- access to Hypervisor.framework
- `com.apple.security.cs.disable-library-validation` -- allows loading
  libkrun from non-system paths (e.g., Homebrew)
- `com.apple.security.cs.allow-dyld-environment-variables` -- allows
  `DYLD_LIBRARY_PATH` to propagate to the runner process (the hypervisor
  entitlement activates hardened runtime, which silently strips `DYLD_*`
  variables without this entitlement)

The propolis-runner binary must be signed:

```bash
codesign --entitlements assets/entitlements.plist --force -s - bin/propolis-runner
```

The `task build-dev-darwin` command handles signing automatically.

## DYLD_LIBRARY_PATH

When using bundled (non-system) libraries, the runner subprocess needs
`DYLD_LIBRARY_PATH` set. propolis handles this automatically via
`libkrun.WithLibDir()` (passed to `libkrun.NewBackend()`).

The hypervisor entitlement activates macOS **hardened runtime**, which silently
strips `DYLD_LIBRARY_PATH` and `DYLD_FALLBACK_LIBRARY_PATH` from child
processes. The `com.apple.security.cs.allow-dyld-environment-variables`
entitlement (in `assets/entitlements.plist`) opts back in. If the runner fails
to find libkrun, verify the binary is signed with all three entitlements.

## Filesystem Permissions (virtiofs)

On macOS, non-root users cannot `chown` files to arbitrary UIDs. When propolis
extracts an OCI image, all files end up owned by the host user. libkrun's
virtiofs FUSE server performs access checks using host-side ownership, so guest
processes running as different UIDs (e.g., root) would get `EACCES` errors.

propolis works around this using the `user.containers.override_stat` extended
attribute, which libkrun's virtiofs server reads to report overridden
uid/gid/mode to the guest. This is the same mechanism used by podman on macOS.
The xattr is set automatically during OCI layer extraction and rootfs cloning
-- no user action is needed.

## Guest Networking

On macOS, libkrun's Hypervisor.framework backend pre-configures the guest
network interface via DHCP before the custom init process runs. propolis
handles this transparently by using idempotent network configuration
(`AddrReplace`/`RouteReplace` instead of `AddrAdd`/`RouteAdd`), so the init
works correctly regardless of whether the interface is already configured.

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
dyld: Library not loaded: @rpath/libkrun.1.dylib
```

The runner can't find libkrun. Set `libkrun.WithLibDir()` (via
`libkrun.NewBackend()`) to the directory containing `libkrun.1.dylib` and
`libkrunfw.5.dylib`.
