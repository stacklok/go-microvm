# propolis Architecture

This document describes the internal architecture of propolis: how it turns an
OCI container image into a running microVM, the two-process model, networking,
state management, and extension points.

## The two-process model

libkrun's `krun_start_enter()` function takes over the calling process. On
success it never returns -- the process becomes the VM supervisor and
eventually calls `exit()` when the guest shuts down. This means we cannot call
it from a normal Go application without losing the Go runtime entirely.

propolis solves this with two processes:

```
+---------------------------+         +---------------------------+
|     Your application      |         |     propolis-runner       |
|  (links propolis library) |         |  (CGO binary, links      |
|                           |  spawn  |   libkrun)                |
|  propolis.Run() --------->|-------->|                           |
|                           |  JSON   |  1. Parse Config (argv[1])|
|  Pure Go, no CGO          |  config |  2. krun.CreateContext()  |
|                           |         |  3. SetVMConfig, SetRoot  |
|  Monitors runner PID      |         |  4. AddNetUnixStream      |
|  Manages gvproxy          |         |  5. krun_start_enter()    |
|  Runs hooks               |         |     (never returns)       |
+---------------------------+         +---------------------------+
         |                                      |
         |  SIGTERM / SIGKILL                    |  VM runs inside
         +------------------------------------->|  this process
```

**Library side** (your application):

- Pulls and caches the OCI image
- Extracts layers into a rootfs directory
- Runs preflight checks and rootfs hooks
- Writes `.krun_config.json` into the rootfs
- Starts the gvproxy networking process
- Spawns `propolis-runner` as a detached subprocess (new session via `setsid`)
- Runs post-boot hooks
- Returns a `*VM` handle for lifecycle management (Stop, Status, Remove)

**Runner side** (`propolis-runner`):

- Receives the full VM configuration as a JSON string in `os.Args[1]`
- Validates the configuration (rootfs exists, vCPUs > 0, RAM > 0)
- Creates a libkrun context via CGO bindings
- Configures vCPUs, RAM, root filesystem, networking, virtio-fs mounts,
  console output
- Calls `krun_start_enter()` which takes over the process

The runner binary is intentionally minimal. It is a thin translation layer
between the JSON config and the libkrun C API. All orchestration logic lives
in the library.

## OCI image pipeline

The pipeline converts an OCI container image into a booted microVM:

```
1. Pull          crane.Pull(imageRef)
                     |
2. Digest        img.Digest() --> cache key (sha256:...)
                     |
3. Cache check   cache.Get(digest) --> hit? return cached rootfs
                     |                  miss? continue
4. Flatten       mutate.Extract(img) --> single tar stream
                     |
5. Extract       extractTar(reader, tmpDir) --> rootfs directory
                     |
                 Security checks:
                   - Path traversal prevention (sanitizeTarPath)
                   - Symlink escape validation
                   - Hardlink boundary enforcement
                   - 30 GiB decompression bomb limit
                     |
6. Cache store   cache.Put(digest, tmpDir) --> atomic rename
                     |
7. Rootfs hooks  hook(rootfsPath, ociConfig) --> modify rootfs
                     |
8. Krun config   Write /.krun_config.json to rootfs
                   {
                     "Cmd": [...],      // from OCI or WithInitOverride
                     "Env": [...],      // merged OCI + defaults
                     "WorkingDir": "/"  // from OCI or default
                   }
                     |
9. Networking    gvproxy.Start() --> Unix socket ready
                     |
10. Spawn        runner.Spawn() --> propolis-runner process
                     |
11. Post-boot    hook(ctx, vm) --> e.g. wait for SSH
```

### Image caching

Images are cached by manifest digest under `~/.config/propolis/cache/` (or
`$PROPOLIS_DATA_DIR/cache/`). The digest `sha256:abc123...` maps to the
directory `sha256-abc123...`. Cache lookups are by directory existence check.
Cache stores use `os.Rename` for atomicity -- if two concurrent pulls race,
the loser's extraction is discarded.

### .krun_config.json

libkrun's built-in init process reads `/.krun_config.json` from the root of
the guest filesystem to determine what program to execute. propolis constructs
this file from the OCI image config (Entrypoint, Cmd, Env, WorkingDir),
with `WithInitOverride` taking precedence over the OCI values. This is the
same mechanism used by krunvm.

## Networking

propolis uses gvproxy for host-guest networking:

```
+-------------------+     Unix socket      +-------------------+
|   Host machine    | (SOCK_STREAM, 4-byte |   Guest VM        |
|                   |  BE length-prefix)   |                   |
|  gvproxy ------------>  virtio-net  -------> eth0            |
|  192.168.127.1    |                      |  192.168.127.2    |
|                   |                      |                   |
|  Port forwards:   |                      |  DHCP from        |
|  localhost:8080 --|--------------------->|  gvproxy gateway   |
|       -> guest:80 |                      |                   |
+-------------------+                      +-------------------+
```

**gvproxy** runs as a separate detached process managed by the `net/gvproxy`
package. It provides:

- A virtual network (192.168.127.0/24) between host and guest
- DHCP for automatic guest IP assignment (192.168.127.2)
- TCP port forwarding from host to guest
- A Unix domain socket that propolis-runner connects to via
  `krun_add_net_unixstream`

The gvproxy process lifecycle:

1. `Start()` launches gvproxy with `-listen-qemu unix://...` and port forward
   arguments
2. Polls for the socket file to appear (100ms intervals, 10s timeout)
3. Returns once the socket is ready
4. `Stop()` sends SIGTERM, falls back to SIGKILL, cleans up the socket file

### The Provider interface

Networking is abstracted behind `net.Provider`:

```go
type Provider interface {
    Start(ctx context.Context, cfg Config) error
    SocketPath() string
    PID() int
    Stop()
}
```

To use a different networking backend, implement this interface and pass it
via `propolis.WithNetProvider()`. The `SocketPath()` return value is passed to
the runner as the Unix socket for `krun_add_net_unixstream`.

## Extension points

```
                    propolis.Run()
                         |
            +------------+------------+
            |                         |
     preflight.Checker          net.Provider
     (KVM, ports, custom)       (gvproxy, custom)
            |                         |
            v                         v
      Pull & Extract            Start networking
            |                         |
            v                         |
      RootFSHook(s)                   |
      (modify rootfs)                 |
            |                         |
            v                         v
      Write .krun_config.json   Socket ready
      (WithInitOverride)              |
            |                         |
            +------------+------------+
                         |
                   Spawn runner
                         |
                         v
                  PostBootHook(s)
                  (SSH wait, config push)
```

### Preflight checks

`preflight.Checker` runs validation before any work begins. Built-in checks:

- **KVM** (Linux): Verifies `/dev/kvm` exists, is a character device, and is
  accessible by the current user
- **HVF** (macOS): No-op (Hypervisor.framework is assumed available on Apple
  Silicon)
- **Ports**: Verifies requested host ports are not already bound

Custom checks are registered via `WithPreflightChecks()`. Each check has a
`Required` flag -- required failures abort the pipeline, non-required failures
log warnings.

### Rootfs hooks

`RootFSHook` functions receive the rootfs path and parsed OCI config after
extraction but before `.krun_config.json` is written. Use cases:

- Inject configuration files
- Install SSH authorized keys
- Modify the init system
- Add overlay files

### Post-boot hooks

`PostBootHook` functions run after the runner process is confirmed alive. The
VM handle is available for inspection. Use cases:

- Wait for SSH to become ready
- Push configuration via SSH
- Register the VM with a service mesh
- Run health checks

## State management

The `state` package provides persistent VM state with file-based locking:

```
~/.config/propolis/
    state.json       <-- VM state (atomic JSON)
    state.lock       <-- flock for exclusive access
    cache/
        sha256-abc.../  <-- cached rootfs by digest
    console.log      <-- guest console output
    vm.log           <-- runner stdout/stderr
    gvproxy.sock     <-- gvproxy Unix socket
    gvproxy.log      <-- gvproxy output
```

### Locking protocol

`Manager.LoadAndLock()` acquires an exclusive flock on `state.lock` and reads
`state.json`. The returned `LockedState` holds the lock until `Release()` is
called. This ensures only one process modifies VM state at a time.

### Atomic writes

`LockedState.Save()` writes to a temporary file in the same directory, then
uses `os.Rename` to atomically replace `state.json`. A crash during write
leaves either the old state intact or the new state fully written -- never a
partial file.

### State fields

```json
{
  "version": 1,
  "active": true,
  "name": "my-vm",
  "image": "alpine:latest",
  "cpus": 2,
  "memory_mb": 1024,
  "pid": 12345,
  "net_provider_pid": 12346,
  "created_at": "2025-01-15T10:00:00Z"
}
```

## Relationship to toolhive-appliance

[toolhive-appliance](https://github.com/stacklok/toolhive-appliance) is the
primary consumer of propolis. It uses the extension points to build a complete
appliance experience:

- `WithInitOverride` to inject a custom init script that starts the appliance
  services
- `WithRootFSHook` to write SSH keys, TLS certificates, and configuration
  files into the rootfs
- `WithPostBoot` to wait for SSH, push runtime configuration, and verify
  service health
- `WithPreflightChecks` to validate appliance-specific prerequisites
- `WithVirtioFS` to share host directories with the guest

propolis provides the general-purpose OCI-to-microVM pipeline. The appliance
layer adds the domain-specific orchestration on top.

## SSH utilities

The `ssh` package provides two capabilities used by consumers like
toolhive-appliance:

- **Key generation**: `GenerateKeyPair()` creates ECDSA P-256 key pairs for
  guest authentication. The private key is written with 0600 permissions.

- **Client**: `ssh.Client` wraps `golang.org/x/crypto/ssh` with convenience
  methods: `Run`, `RunSudo`, `RunStream`, `CopyTo`, `CopyFrom`, and
  `WaitForReady`. The `WaitForReady` method polls the guest SSH server at 2s
  intervals until a connection succeeds, which is the standard pattern for
  post-boot hooks.
