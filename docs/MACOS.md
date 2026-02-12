# macOS Support

propolis supports macOS on Apple Silicon (arm64) using Hypervisor.framework.

## Requirements

- **Apple Silicon** (M1/M2/M3/M4) -- Intel Macs are not supported
- **macOS 11+** -- Hypervisor.framework requires Big Sur or later
- **libkrun** and **libkrunfw** -- install via Homebrew or build from source
- **gvproxy** -- for networking (built from source or Homebrew)

## Key Platform Differences

| Aspect | Linux | macOS |
|--------|-------|-------|
| Hypervisor | KVM (`/dev/kvm`) | Hypervisor.framework |
| Shared libraries | `.so` (libkrun.so.1, libkrunfw.so.5) | `.dylib` (libkrun.dylib, libkrunfw.dylib) |
| Library path env | `LD_LIBRARY_PATH` | `DYLD_LIBRARY_PATH` |
| Code signing | Not required | Required (hypervisor entitlement) |
| PID identity check | `/proc/<pid>/exe` readlink | `signal(0)` best-effort |

## Code Signing

macOS requires binaries that use Hypervisor.framework to be signed with the
`com.apple.security.hypervisor` entitlement. Without this, the process will
crash with `EXC_BAD_ACCESS` when trying to create a VM context.

The propolis-runner binary must be signed:

```bash
codesign --entitlements entitlements.plist --force -s - bin/propolis-runner
```

Where `entitlements.plist` contains:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.hypervisor</key>
    <true/>
</dict>
</plist>
```

The `task build-dev-darwin` command handles signing automatically.

## DYLD_LIBRARY_PATH

When using bundled (non-system) libraries, the runner subprocess needs
`DYLD_LIBRARY_PATH` set. propolis handles this automatically via
`WithLibDir()`. macOS SIP (System Integrity Protection) strips
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
codesign --entitlements entitlements.plist --force -s - bin/propolis-runner
```

### DYLD_LIBRARY_PATH issues

```
dyld: Library not loaded: @rpath/libkrun.dylib
```

The runner can't find libkrun. Set `WithLibDir()` to the directory
containing `libkrun.dylib` and `libkrunfw.dylib`.
