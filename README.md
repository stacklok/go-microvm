<div align="center">
  <img src="assets/propolis.png" alt="propolis mascot" width="250" />

  <h1>propolis</h1>

  <p><strong>Run OCI container images as microVMs with libkrun.</strong></p>

  <p>
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#architecture">Architecture</a> &middot;
    <a href="docs/ARCHITECTURE.md">Docs</a> &middot;
    <a href="#license">License</a>
  </p>
</div>

---

propolis is a Go library and runner binary that turns any OCI container image
into a lightweight virtual machine. It pulls the image, flattens its layers
into a rootfs, configures in-process networking, and boots the result using
[libkrun](https://github.com/containers/libkrun) -- all in a single function
call.

You would use propolis when you need stronger isolation than containers provide
but want to keep the OCI image workflow you already have. The framework handles
image caching, preflight validation, port forwarding, virtio-fs mounts, and
process lifecycle so you can focus on what runs inside the VM.

propolis was extracted from
[toolhive-appliance](https://github.com/stacklok/toolhive-appliance) to
provide a reusable, general-purpose OCI-to-microVM pipeline. toolhive-appliance
remains the primary consumer of this library.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Advanced Usage](#advanced-usage)
- [Package Overview](#package-overview)
- [Build](#build)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Troubleshooting](#troubleshooting)
- [Relationship to toolhive-appliance](#relationship-to-toolhive-appliance)
- [License](#license)

## Prerequisites

propolis requires hardware virtualization support and a few system packages.

### Linux -- Fedora

```bash
# Install libkrun development headers
sudo dnf install libkrun-devel

# Ensure your user has KVM access
sudo usermod -aG kvm $USER
# Log out and back in for the group change to take effect
```

### Linux -- Ubuntu / Debian

libkrun is not yet packaged for Debian-based distributions. You must build it
from source:

```bash
# Install build dependencies
sudo apt install build-essential libssl-dev pkg-config python3 patchelf

# Clone and build libkrun
git clone https://github.com/containers/libkrun.git
cd libkrun
make
sudo make install
sudo ldconfig

# Ensure your user has KVM access
sudo usermod -aG kvm $USER
```

### macOS (Apple Silicon)

```bash
# Install libkrun via Homebrew
brew install libkrun

# Or build from source:
git clone https://github.com/containers/libkrun.git
cd libkrun
make
sudo make install
```

On macOS, Hypervisor.framework provides hardware virtualization and is available
on all supported Apple Silicon Macs. No `/dev/kvm` equivalent is needed.

### All Platforms -- Verify KVM Access (Linux)

```bash
# Check that /dev/kvm exists and is accessible
ls -la /dev/kvm

# If you get "permission denied", add your user to the kvm group:
sudo usermod -aG kvm $USER
# Then log out and log back in.

# Verify KVM modules are loaded
lsmod | grep kvm
# If empty, load them:
sudo modprobe kvm kvm_intel   # Intel CPUs
sudo modprobe kvm kvm_amd     # AMD CPUs
```

### Go Toolchain

propolis requires **Go 1.25.7** or later. The library packages (everything
except `krun` and `propolis-runner`) do not require CGO and compile with
`CGO_ENABLED=0`. The runner binary requires `CGO_ENABLED=1` and `libkrun-devel`.

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/stacklok/propolis"
)

func main() {
    ctx := context.Background()

    vm, err := propolis.Run(ctx, "alpine:latest",
        propolis.WithPorts(propolis.PortForward{Host: 8080, Guest: 80}),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer vm.Stop(ctx)

    info, _ := vm.Status(ctx)
    log.Printf("VM %s running (pid %d)", info.Name, info.PID)

    // The VM is now serving on localhost:8080.
    // Block until interrupted, or integrate with your own lifecycle.
    select {}
}
```

`propolis.Run` executes the full pipeline: preflight checks, OCI image pull,
layer extraction, rootfs caching, networking setup, subprocess spawn, and
post-boot hooks. It returns a `*VM` handle that you use to query status, stop,
or remove the VM.

## Advanced Usage

For appliance-style deployments (like
[toolhive-appliance](https://github.com/stacklok/toolhive-appliance)),
propolis exposes hooks and overrides at every stage of the pipeline:

```go
package main

import (
    "context"
    "os"
    "path/filepath"

    "github.com/stacklok/propolis"
    "github.com/stacklok/propolis/hypervisor/libkrun"
    "github.com/stacklok/propolis/image"
    "github.com/stacklok/propolis/preflight"
    "github.com/stacklok/propolis/ssh"
)

func main() {
    ctx := context.Background()

    vm, err := propolis.Run(ctx, "my-appliance:latest",
        // Name the VM (defaults to "propolis").
        propolis.WithName("my-appliance"),

        // Configure VM resources.
        // vCPUs default to 1, memory defaults to 512 MiB.
        // Stock libkrunfw caps vCPUs at 8.
        propolis.WithCPUs(4),
        propolis.WithMemory(2048),

        // Port forwards from host to guest.
        propolis.WithPorts(
            propolis.PortForward{Host: 443, Guest: 443},
            propolis.PortForward{Host: 2222, Guest: 22},
        ),

        // Replace the OCI ENTRYPOINT/CMD with a custom init script.
        // The command is written into /.krun_config.json and executed
        // by libkrun's built-in init process (PID 1).
        propolis.WithInitOverride("/sbin/my-init"),

        // Inject files into the rootfs before boot.
        // Hooks run after image extraction but before .krun_config.json
        // is written, so they can modify anything in the filesystem.
        propolis.WithRootFSHook(func(rootfs string, cfg *image.OCIConfig) error {
            return os.WriteFile(
                filepath.Join(rootfs, "etc", "my-app.conf"),
                []byte("key=value\n"), 0o644,
            )
        }),

        // Run setup after the VM process is alive.
        // Common use: wait for SSH, push configuration, run health checks.
        propolis.WithPostBoot(func(ctx context.Context, vm *propolis.VM) error {
            keyPath := filepath.Join(vm.DataDir(), "id_ecdsa")
            sshClient := ssh.NewClient("127.0.0.1", 2222, "root", keyPath)
            return sshClient.WaitForReady(ctx)
        }),

        // Mount a host directory into the guest via virtio-fs.
        propolis.WithVirtioFS(propolis.VirtioFSMount{
            Tag: "shared", HostPath: "/srv/data",
        }),

        // Use a custom data directory for state, caches, and logs.
        // Defaults to ~/.config/propolis or $PROPOLIS_DATA_DIR.
        propolis.WithDataDir("/var/lib/my-appliance"),

        // Configure the libkrun backend with a specific runner binary
        // and library search path. These options are backend-specific.
        propolis.WithBackend(libkrun.NewBackend(
            libkrun.WithRunnerPath("/usr/local/bin/propolis-runner"),
            libkrun.WithLibDir("/opt/libs"),
        )),

        // Add custom preflight checks beyond the built-in defaults
        // (KVM access, disk space, system resources, port availability).
        propolis.WithPreflightChecks(
            preflight.PortCheck(443, 2222),
            preflight.Check{
                Name:        "connectivity",
                Description: "Verify registry is reachable",
                Run: func(ctx context.Context) error {
                    // Custom validation logic here.
                    return nil
                },
                Required: true,
            },
        ),

        // Provide a custom image cache location.
        propolis.WithImageCache(image.NewCache("/var/cache/propolis")),
    )
    if err != nil {
        panic(err)
    }
    defer vm.Stop(ctx)

    // VM lifecycle methods:
    //   vm.Stop(ctx)      -- SIGTERM, then SIGKILL after 30s
    //   vm.Status(ctx)    -- returns VMInfo{Name, Active, ID, Ports}
    //   vm.Remove(ctx)    -- stop + clean up
    //   vm.Name()         -- VM name
    //   vm.ID()           -- backend-specific identifier (e.g. PID string for libkrun)
    //   vm.DataDir()      -- data directory path
    //   vm.RootFSPath()   -- extracted rootfs path
    //   vm.Ports()        -- configured port forwards
}
```

### Complete Option Reference

| Option | Description | Default |
|--------|-------------|---------|
| `WithName(s)` | VM name for identification | `"propolis"` |
| `WithCPUs(n)` | Virtual CPUs (max 8 with stock libkrunfw, max 255 hard limit) | `1` |
| `WithMemory(mib)` | RAM in MiB | `512` |
| `WithPorts(...)` | TCP port forwards from host to guest | none |
| `WithInitOverride(cmd...)` | Replace OCI ENTRYPOINT/CMD | OCI config |
| `WithRootFSPath(path)` | Use pre-built rootfs directory, skip OCI image pull | none |
| `WithRootFSHook(...)` | Modify rootfs before boot | none |
| `WithPostBoot(...)` | Run logic after VM process starts | none |
| `WithNetProvider(p)` | Replace default runner-side networking with a custom provider | runner-side vnet |
| `WithFirewallRules(...)` | Firewall rules for frame-level packet filtering | none |
| `WithFirewallDefaultAction(action)` | Default firewall action when no rule matches | `Allow` |
| `WithPreflightChecker(c)` | Replace entire preflight checker | platform defaults |
| `WithPreflightChecks(...)` | Add custom pre-boot checks | KVM + resources |
| `WithVirtioFS(...)` | Host directory mounts via virtio-fs | none |
| `WithDataDir(p)` | State, cache, and log directory | `~/.config/propolis` |
| `WithCleanDataDir()` | Remove existing data dir contents before boot | disabled |
| `WithEgressPolicy(p)` | Restrict outbound traffic to allowed DNS hostnames | none |
| `WithImageCache(c)` | Custom image cache instance | `$dataDir/cache/` |
| `WithImageFetcher(f)` | Custom image fetcher for OCI retrieval | local-then-remote |
| `WithBackend(b)` | Hypervisor backend (e.g. `libkrun.NewBackend(...)`) | libkrun |

## Package Overview

| Package | CGO? | Description |
|---------|------|-------------|
| `propolis` (root) | No | Top-level API: `Run()`, `VM` type, functional options, hook types |
| `hypervisor` | No | `Backend` and `VMHandle` interfaces, `VMConfig`, `InitConfig` types |
| `hypervisor/libkrun` | No | libkrun backend: spawns propolis-runner subprocess, `WithRunnerPath`/`WithLibDir`/`WithSpawner` |
| `image` | No | OCI image pull via `ImageFetcher`, layer flattening, rootfs extraction |
| `image/disk` | No | Disk image download with decompression (gzip/bzip2/xz) |
| `krun` | **Yes** | CGO bindings to libkrun C API (context, VM config, `StartEnter`) |
| `hooks` | No | RootFS hook factories: `InjectAuthorizedKeys`, `InjectFile`, `InjectBinary`, `InjectEnvFile` |
| `extract` | No | Binary bundle caching with SHA-256 versioning and cross-process locking |
| `guest/*` | No | Guest-side boot orchestration, hardening, SSH server (Linux-only, `//go:build linux`) |
| `net` | No | `Provider` interface and `Config`/`PortForward` types |
| `net/firewall` | No | Frame-level packet filtering with stateful connection tracking |
| `net/egress` | No | DNS-based egress policy: intercepts DNS, creates dynamic firewall rules |
| `net/hosted` | No | Hosted `net.Provider` running VirtualNetwork in caller's process with HTTP services |
| `net/topology` | No | Shared network topology constants (subnet, gateway, IPs, MTU) |
| `preflight` | No | `Checker` interface, `Check` struct, built-in KVM/HVF and port checks |
| `runner` | No | `Spawner` / `ProcessHandle` interfaces for managing the propolis-runner subprocess |
| `runner/cmd/propolis-runner` | **Yes** | The runner binary (calls `krun.StartEnter`, never returns) |
| `ssh` | No | ECDSA key generation and SSH client for guest communication |
| `state` | No | flock-based state persistence with atomic JSON writes |
| `internal/pathutil` | No | Path traversal validation for safe file operations |

Only `krun` and `runner/cmd/propolis-runner` require CGO and `libkrun-devel`.
All other packages are pure Go and can be imported and tested with
`CGO_ENABLED=0`.

## Build

propolis uses [Task](https://taskfile.dev/) as its build tool. Run
`task --list` for all available commands.

| Command | Description |
|---------|-------------|
| `task build-dev` | Build runner for development on Linux (requires system `libkrun-devel`, `CGO_ENABLED=1`) |
| `task build-dev-darwin` | Build runner on macOS (requires Homebrew libkrun, signs with entitlements) |
| `task build-dev-race` | Build runner with Go race detector enabled |
| `task test` | Run all tests with race detector (`go test -v -race ./...`) |
| `task test-coverage` | Run tests with coverage, generates `coverage.html` |
| `task lint` | Run `golangci-lint` |
| `task lint-fix` | Run linter and auto-fix issues |
| `task fmt` | Format code (`go fmt` + `goimports`) |
| `task tidy` | Run `go mod tidy` |
| `task verify` | Run fmt, lint, and test in sequence (CI pipeline) |
| `task version` | Print version, commit, and build date from git |
| `task clean` | Remove `bin/` directory and coverage files |

### Testing Without CGO

The library packages do not require CGO and can be validated separately:

```bash
# Test pure-Go packages only (no libkrun needed)
CGO_ENABLED=0 go test $(go list ./... | grep -v krun | grep -v propolis-runner)

# Vet pure-Go packages
CGO_ENABLED=0 go vet $(go list ./... | grep -v krun | grep -v propolis-runner)
```

## Architecture

propolis uses a **two-process model**:

```
+---------------------------+         +---------------------------+
|     Your application      |         |     propolis-runner       |
|  (links propolis library) |  spawn  |  (CGO binary, links      |
|                           |-------->|   libkrun)                |
|  propolis.Run()           |  JSON   |                           |
|                           |  config |  1. Parse Config (argv[1])|
|  Pure Go, no CGO          |         |  2. krun.CreateContext()  |
|                           |         |  3. SetVMConfig, SetRoot  |
|  Monitors runner PID      |         |  4. AddNetUnixStream      |
|  In-process networking    |         |  5. krun_start_enter()    |
|  Runs hooks               |         |     (never returns)       |
+---------------------------+         +---------------------------+
         |                                      |
         |  SIGTERM / SIGKILL                    |  VM runs inside
         +------------------------------------->|  this process
```

1. **Your application** links the propolis library (pure Go, no CGO). It pulls
   the OCI image, configures networking, runs preflight checks, and spawns a
   subprocess.

2. **propolis-runner** is a small CGO binary that receives the VM configuration
   as JSON in `argv[1]`. It calls libkrun's C API to configure the VM context,
   then calls `krun_start_enter()` -- which **never returns** on success. The
   calling process becomes the VM supervisor until the guest shuts down.

This separation exists because `krun_start_enter()` takes over the process. If
it were called from your application directly, you would lose control of the
Go runtime.

### OCI-to-VM Pipeline

```
  Pull image (crane)
       |
  Flatten layers (mutate.Extract)
       |
  Extract to rootfs directory (with security checks)
       |
  Run rootfs hooks (optional, caller-provided)
       |
  Write /.krun_config.json
       |
  Start networking (in-process vnet)
       |
  Spawn propolis-runner subprocess
       |
  Runner calls krun_start_enter()
       |
  Run post-boot hooks (optional, caller-provided)
```

### Networking

```
+-------------------+     Unix socket      +-------------------+
|   Host machine    | (SOCK_STREAM, 4-byte |   Guest VM        |
|                   |  BE length-prefix)   |                   |
|  VirtualNetwork ------>  virtio-net  -------> eth0            |
|  (in-process)     |                      |  192.168.127.2    |
|  192.168.127.1    |                      |                   |
|                   |                      |  DHCP from        |
|  Port forwards:   |                      |  VirtualNetwork   |
|  localhost:8080 --|--------------------->|  gateway           |
|       -> guest:80 |                      |                   |
+-------------------+                      +-------------------+
```

By default, the runner creates an in-process VirtualNetwork (gvisor-tap-vsock)
providing a virtual network (192.168.127.0/24), DHCP, DNS, and TCP port
forwarding. For advanced use cases, `WithNetProvider()` moves the network stack
to the caller's process -- the `net/hosted` package provides a ready-made
provider that also supports HTTP services on the gateway IP. An optional
frame-level firewall with stateful connection tracking can be enabled via
`WithFirewallRules()`. See [docs/NETWORKING.md](docs/NETWORKING.md) for a
deep dive.

### Extension Points

- **`hypervisor.Backend`** -- pluggable hypervisor backend (default: libkrun)
- **`net.Provider`** -- replace default in-process networking
- **`preflight.Checker`** -- add custom pre-boot validations
- **`RootFSHook`** -- modify the rootfs before VM boot
- **`PostBootHook`** -- run logic after the VM process is confirmed alive
- **`WithInitOverride`** -- replace the OCI ENTRYPOINT/CMD entirely
- **`WithEgressPolicy`** -- restrict outbound traffic to allowed DNS hostnames

For a detailed architecture walkthrough, see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Security Model

### Guest-VMM Trust Boundary

libkrun runs the guest and VMM in the same process and security context. The
microVM provides hardware-level isolation via KVM (Linux) or
Hypervisor.framework (macOS), but the VMM itself is not sandboxed from the
host process. This is the same model used by krunvm and crun+libkrun. Treat
the VM as a stronger isolation boundary than containers but weaker than a fully
sandboxed hypervisor like Firecracker.

### Tar Extraction Security

When extracting OCI image layers, propolis applies multiple defenses against
malicious tar archives:

- **Path traversal prevention**: `sanitizeTarPath` rejects absolute paths and
  paths containing `..` components that would resolve outside the rootfs.
- **Symlink traversal prevention**: `mkdirAllNoSymlink` creates directories one
  component at a time and refuses to follow symlinks when creating parent
  directories. `validateNoSymlinkLeaf` prevents writing through symlinks.
- **Hardlink boundary enforcement**: hard links are validated to ensure both
  source and target remain within the rootfs directory.
- **Decompression bomb limit**: extraction is capped at 30 GiB via an
  `io.LimitedReader` to prevent resource exhaustion.

### Process Identity Verification

When stopping a VM, the `runner.Process.IsAlive()` method sends signal 0 to the
PID to verify the process exists before sending SIGTERM. This prevents sending
signals to unrelated processes if the PID has been reused. The stop sequence
uses SIGTERM first, then falls back to SIGKILL after a 30-second timeout.

## Troubleshooting

### VM Fails to Start

```bash
# 1. Check KVM availability (Linux)
ls -la /dev/kvm
# If missing: sudo modprobe kvm kvm_intel  (or kvm_amd)
# If permission denied: sudo usermod -aG kvm $USER

# 2. Check console output for guest-side errors
cat ~/.config/propolis/console.log

# 3. Check runner stderr for host-side errors
cat ~/.config/propolis/vm.log

# 4. Verify the runner binary is available
which propolis-runner
# Or check next to your binary
```

### Image Pull Fails

```bash
# Check registry connectivity
crane manifest alpine:latest

# Check Docker/Podman auth for private registries
cat ~/.docker/config.json

# Try pulling manually to see detailed errors
crane pull alpine:latest /tmp/test.tar
```

### Port Conflicts

```bash
# Check which process is using a port
ss -tlnp | grep ':8080'

# Or use the propolis preflight check directly:
# propolis.WithPreflightChecks(preflight.PortCheck(8080))
```

### macOS-Specific Issues

- The runner binary must be code-signed with Hypervisor.framework entitlements.
  The `task build-dev-darwin` command handles this automatically.
- If using bundled libraries, set `DYLD_LIBRARY_PATH` (not `LD_LIBRARY_PATH`).
  The `libkrun.WithLibDir` backend option handles this for the runner subprocess.

## Relationship to toolhive-appliance

propolis was extracted from
[toolhive-appliance](https://github.com/stacklok/toolhive-appliance) to
provide a reusable OCI-to-microVM pipeline. The appliance uses the extension
points to build a complete appliance experience:

- `WithInitOverride` to inject a custom init script that starts k3s and
  appliance services
- `WithRootFSHook` to write SSH keys, TLS certificates, and configuration
  files into the rootfs before boot
- `WithPostBoot` to wait for SSH, push runtime configuration, sync kubeconfig,
  and verify service health
- `WithPreflightChecks` to validate appliance-specific prerequisites (disk
  space, connectivity)
- `WithVirtioFS` to share host directories with the guest
- `WithDataDir` to use appliance-specific state directories
- `WithBackend(libkrun.NewBackend(...))` with `libkrun.WithRunnerPath` and
  `libkrun.WithLibDir` to point at embedded binaries

propolis provides the general-purpose pipeline. The appliance layer adds the
domain-specific orchestration on top. If you are building something similar --
a self-contained binary that boots a VM from an OCI image -- propolis gives you
the building blocks.

## License

Apache 2.0 -- see [LICENSE](LICENSE).
