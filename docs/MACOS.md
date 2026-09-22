# macOS Support

go-microvm supports macOS on Apple Silicon (arm64) using Hypervisor.framework.

## Requirements

- **Apple Silicon** (M1/M2/M3/M4) -- Intel Macs are not supported
- **macOS 11+** -- Hypervisor.framework requires Big Sur or later
- **libkrun** and **libkrunfw** -- install via Homebrew (see below) or build from source

## Installing libkrun

The easiest way to install libkrun on macOS is via Homebrew:

```bash
brew tap slp/krun
brew trust slp/krun
brew install libkrun libkrunfw
```

Homebrew 6.0+ requires third-party taps to be trusted before installing from
them. `libkrun`/`libkrunfw` pull in other formulae from the same tap (e.g.
`virglrenderer`) as dependencies, so trusting only the two top-level formulae
by fully-qualified name is not enough -- the whole tap must be trusted.

This installs the libraries and headers into Homebrew's prefix (`/opt/homebrew`
on Apple Silicon, `/usr/local` on Intel). The CGO directives in go-microvm
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

The go-microvm-runner binary must be signed:

```bash
codesign --entitlements assets/entitlements.plist --force -s - bin/go-microvm-runner
```

The `task build-dev-darwin` command handles signing automatically.

## DYLD_LIBRARY_PATH

When using bundled (non-system) libraries, the runner subprocess needs
`DYLD_LIBRARY_PATH` set. go-microvm handles this automatically via
`libkrun.WithLibDir()` (passed to `libkrun.NewBackend()`).

The hypervisor entitlement activates macOS **hardened runtime**, which silently
strips `DYLD_LIBRARY_PATH` and `DYLD_FALLBACK_LIBRARY_PATH` from child
processes. The `com.apple.security.cs.allow-dyld-environment-variables`
entitlement (in `assets/entitlements.plist`) opts back in. If the runner fails
to find libkrun, verify the binary is signed with all three entitlements.

## Filesystem Permissions (virtiofs)

On macOS, non-root users cannot `chown` files to arbitrary UIDs. When go-microvm
extracts an OCI image, all files end up owned by the host user. libkrun's
virtiofs FUSE server performs access checks using host-side ownership, so guest
processes running as different UIDs (e.g., root) would get `EACCES` errors.

go-microvm works around this using the `user.containers.override_stat` extended
attribute, which libkrun's virtiofs server reads to report overridden
uid/gid/mode to the guest. This is the same mechanism used by podman on macOS.
The xattr is set automatically during OCI layer extraction and rootfs cloning
-- no user action is needed.

### virtio-fs shared directory ownership

A writable `microvm.VirtioFSMount` with `OverrideUID > 0` is strictly prepared
before networking starts. `OverrideGID` defaults to the UID. Startup fails on
inaccessible entries, malformed metadata, unsupported special files, or xattr
errors instead of continuing with partly incorrect guest ownership. This is a
deliberate compatibility change from the previous best-effort behavior. There is
no best-effort toggle for opted-in writable mounts.

```go
microvm.WithVirtioFS(microvm.VirtioFSMount{
    Tag:         "shared",
    HostPath:    "/srv/vm-share",
    OverrideUID: 65532,
    OverrideGID: 65532,
})
```

Read-only mounts are not prepared automatically, and explicit preparation does
not change their export flags. Prepare the backing tree first when the host OS
permits its xattr operation, then request a read-only export:

```go
if err := virtiofs.PrepareOwnership(ctx, "/srv/vm-share", ".", 65532, 65532); err != nil {
    return err
}
vm, err := microvm.Run(ctx, image,
    microvm.WithVirtioFS(microvm.VirtioFSMount{
        Tag: "shared", HostPath: "/srv/vm-share", ReadOnly: true,
    }),
)
```

The same API can prepare one replaced file or subtree while a VM is running,
without rescanning siblings:

```go
if err := virtiofs.PrepareOwnership(ctx, "/srv/vm-share", "results/job-42", 65532, 65532); err != nil {
    return err
}
```

The root must be a real directory, and the selected target must be `.` or a
relative path. Trusted ancestor symlinks such as macOS `/var` are allowed, but
the final root and every explicit relative component are opened without
following symlinks. Descendant symlinks are skipped. Only directories and
regular files are supported. Keep the export root stable for the VM lifetime:
libkrun pins that host mount, so replacing the root pathname does not retarget a
running guest.

Host ownership and mode are unchanged. New metadata derives the guest mode from
the host inode. Existing metadata retains its permission, set-ID, and sticky
bits (including guest `chmod` changes), while preparation corrects the file type
and applies the requested uid/gid. Matching metadata is not rewritten.

Creating or changing metadata requires the host OS permission to write xattrs.
An ordinary unprivileged user therefore cannot normally annotate an unannotated
`0400` file. `PrepareOwnership` returns a path-specific permission error and
leaves its host mode and IDs intact. A read-only virtio-fs export does not grant
xattr-write permission on its backing inodes.

Preparation is nontransactional. Callers must synchronize it with host rename,
creation, and replacement and with guest access or `chmod`. There is no atomic
visibility or cache-invalidation guarantee; a descriptor held across replacement
continues to refer to the old inode. A hard link in the authorized tree
authorizes changing the xattr on that inode, including names outside the tree.
The caller must also trust and protect the root's parent while the root descriptor
is acquired; subsequent traversal is descriptor-relative and confined beneath
the acquired root.

## Guest Networking

On macOS, libkrun's Hypervisor.framework backend pre-configures the guest
network interface via DHCP before the custom init process runs. go-microvm
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

The go-microvm-runner binary is not signed with the hypervisor entitlement.
Re-sign it:

```bash
codesign --entitlements assets/entitlements.plist --force -s - bin/go-microvm-runner
```

### DYLD_LIBRARY_PATH issues

```
dyld: Library not loaded: @rpath/libkrun.1.dylib
```

The runner can't find libkrun. Set `libkrun.WithLibDir()` (via
`libkrun.NewBackend()`) to the directory containing `libkrun.1.dylib` and
`libkrunfw.5.dylib`.
