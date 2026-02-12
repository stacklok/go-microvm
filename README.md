# propolis

**Run OCI container images as microVMs with libkrun.**

propolis is a Go library and runner binary that turns any OCI container image
into a lightweight virtual machine. It pulls the image, flattens its layers
into a rootfs, configures networking via gvproxy, and boots the result using
[libkrun](https://github.com/containers/libkrun) -- all in a single function
call.

You would use propolis when you need stronger isolation than containers provide
but want to keep the OCI image workflow you already have. The framework handles
image caching, preflight validation, port forwarding, virtio-fs mounts, and
process lifecycle so you can focus on what runs inside the VM.

## Quick start

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

## Advanced usage

For appliance-style deployments (like
[toolhive-appliance](https://github.com/stacklok/toolhive-appliance)),
propolis exposes hooks and overrides at every stage of the pipeline:

```go
vm, err := propolis.Run(ctx, "my-appliance:latest",
    propolis.WithName("my-appliance"),
    propolis.WithCPUs(4),
    propolis.WithMemory(2048),
    propolis.WithPorts(
        propolis.PortForward{Host: 443, Guest: 443},
        propolis.PortForward{Host: 2222, Guest: 22},
    ),

    // Replace the OCI ENTRYPOINT/CMD with a custom init script.
    propolis.WithInitOverride("/sbin/my-init"),

    // Inject files into the rootfs before boot.
    propolis.WithRootFSHook(func(rootfs string, cfg *image.OCIConfig) error {
        return os.WriteFile(
            filepath.Join(rootfs, "etc", "my-app.conf"),
            []byte("key=value\n"), 0o644,
        )
    }),

    // Run setup after the VM process is alive.
    propolis.WithPostBoot(func(ctx context.Context, vm *propolis.VM) error {
        sshClient := ssh.NewClient("127.0.0.1", 2222, "root", keyPath)
        return sshClient.WaitForReady(ctx)
    }),

    // Mount a host directory into the guest via virtio-fs.
    propolis.WithVirtioFS(propolis.VirtioFSMount{
        Tag: "shared", HostPath: "/srv/data",
    }),

    // Use a custom data directory for state and caches.
    propolis.WithDataDir("/var/lib/my-appliance"),

    // Point to a specific runner binary.
    propolis.WithRunnerPath("/usr/local/bin/propolis-runner"),
)
```

## Package overview

| Package | Description |
|---------|-------------|
| `propolis` (root) | Top-level API: `Run()`, `VM`, options, hooks |
| `image` | OCI image pull, layer flattening, rootfs extraction, `.krun_config.json` |
| `krun` | CGO bindings to libkrun (context creation, VM config, `krun_start_enter`) |
| `net` | Network provider interface (`Provider`) and types |
| `net/gvproxy` | Default `net.Provider` implementation using gvproxy |
| `preflight` | Extensible pre-boot checks (KVM access, port availability) |
| `runner` | Subprocess management: spawn/stop the `propolis-runner` binary |
| `runner/cmd/propolis-runner` | The runner binary itself (calls into `krun`) |
| `ssh` | SSH key generation and client for guest communication |
| `state` | VM state persistence with flock-based locking and atomic JSON writes |

## Prerequisites

**Linux (primary target):**

- `libkrun-devel` -- development headers for libkrun
- `gvproxy` -- userspace networking (usually from `gvisor-tap-vsock` or your
  distribution's container tools)
- `/dev/kvm` -- hardware virtualization (your user must be in the `kvm` group)

**macOS (Apple Silicon):**

- `libkrun` -- via Homebrew or built from source
- Hypervisor.framework -- available on all supported Apple Silicon Macs

## Build

propolis uses [Task](https://taskfile.dev/) as its build tool.

```bash
# Build the runner binary (requires libkrun-devel and CGO)
task build-runner

# Build with race detector for development
task build-runner-dev

# Run library tests (no CGO required)
task test

# Lint
task lint

# Format and tidy
task fmt && task tidy
```

The library packages (`propolis`, `image`, `net`, `preflight`, `ssh`, `state`)
do not require CGO and can be tested with `CGO_ENABLED=0`. Only the `krun`
package and the `propolis-runner` binary require CGO and `libkrun-devel`.

## Architecture

propolis uses a **two-process model**:

1. **Your application** links the propolis library (pure Go, no CGO). It pulls
   the OCI image, configures networking, runs preflight checks, and spawns a
   subprocess.

2. **propolis-runner** is a small CGO binary that receives the VM configuration
   as JSON in argv[1]. It calls libkrun's C API to configure the VM context,
   then calls `krun_start_enter()` -- which **never returns** on success. The
   calling process becomes the VM supervisor until the guest shuts down.

This separation exists because `krun_start_enter()` takes over the process. If
it were called from your application directly, you would lose control of the
Go runtime.

### OCI-to-VM pipeline

```
  Pull image (crane)
       |
  Flatten layers (mutate.Extract)
       |
  Extract to rootfs directory
       |
  Run rootfs hooks (optional)
       |
  Write /.krun_config.json
       |
  Start gvproxy (networking)
       |
  Spawn propolis-runner subprocess
       |
  Runner calls krun_start_enter()
       |
  Run post-boot hooks (optional)
```

### Extension points

- **`net.Provider`** -- replace gvproxy with any networking backend
- **`preflight.Check`** -- add custom pre-boot validations
- **`RootFSHook`** -- modify the rootfs before `.krun_config.json` is written
- **`PostBootHook`** -- run logic after the VM process is confirmed alive
- **`WithInitOverride`** -- replace the OCI ENTRYPOINT/CMD entirely

For a detailed architecture walkthrough, see
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## License

Apache 2.0 -- see [LICENSE](LICENSE).
