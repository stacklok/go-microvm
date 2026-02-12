# propolis Architecture

This document describes the internal architecture of propolis: how it turns an
OCI container image into a running microVM, the two-process model, networking,
state management, security measures, and extension points.

## Table of Contents

- [The Two-Process Model](#the-two-process-model)
- [OCI Image Pipeline](#oci-image-pipeline)
- [Image Caching](#image-caching)
- [.krun_config.json](#krun_configjson)
- [Networking](#networking)
- [Extension Points](#extension-points)
- [Preflight Check System](#preflight-check-system)
- [State Management](#state-management)
- [Security Model](#security-model)
- [SSH Utilities](#ssh-utilities)
- [Relationship to toolhive-appliance](#relationship-to-toolhive-appliance)

## The Two-Process Model

libkrun's `krun_start_enter()` function takes over the calling process. On
success it never returns -- the process becomes the VM supervisor and
eventually calls `exit()` when the guest shuts down. This means we cannot call
it from a normal Go application without losing the Go runtime entirely.

propolis solves this with two processes:

```
+----------------------------------+       +----------------------------------+
|        Your application          |       |        propolis-runner           |
|   (links propolis library)       |       |   (CGO binary, links libkrun)   |
|                                  |       |                                  |
|   1. Preflight checks            | spawn |   1. Parse Config from argv[1]   |
|   2. Pull & cache OCI image      |------>|   2. Validate (rootfs, vCPUs>0)  |
|   3. Extract layers to rootfs    | JSON  |   3. krun.CreateContext()         |
|   4. Run rootfs hooks            | config|   4. SetVMConfig(vCPUs, RAM)      |
|   5. Write .krun_config.json     |       |   5. SetRoot(rootfsPath)          |
|   6. Start gvproxy (networking)  |       |   6. AddNetUnixStream(socket)     |
|   7. Spawn propolis-runner       |       |   7. AddVirtioFS (for each mount) |
|   8. Run post-boot hooks         |       |   8. SetConsoleOutput(logPath)    |
|   9. Return *VM handle           |       |   9. krun_start_enter()           |
|                                  |       |      (NEVER RETURNS ON SUCCESS)   |
|   Pure Go, no CGO                |       |                                  |
|   Monitors runner PID            |       |   Process becomes VM supervisor   |
|   Manages gvproxy lifecycle      |       |   Exits when guest shuts down     |
+----------------------------------+       +----------------------------------+
         |                                              |
         |  SIGTERM (graceful) / SIGKILL (30s timeout)  |
         +--------------------------------------------->|
```

### Library Side (your application)

The library is pure Go with no CGO dependency. It performs the following steps
in `propolis.Run()`:

1. **Preflight checks** -- Runs all registered `preflight.Checker` validations.
   Built-in checks verify KVM/HVF access, disk space, and system resources.
   Custom checks can be added via `WithPreflightChecks()`. Required check
   failures abort the pipeline; non-required failures log warnings.

2. **Image pull and cache** -- Uses `crane.Pull()` from
   `google/go-containerregistry` to fetch the OCI image. Computes the manifest
   digest for cache lookup. On cache miss, flattens layers via
   `mutate.Extract()` and extracts the tar stream to a temporary directory with
   full security checks.

3. **Rootfs hooks** -- Runs caller-provided `RootFSHook` functions in
   registration order. Each receives the rootfs path and parsed `OCIConfig`.

4. **Write .krun_config.json** -- Constructs `KrunConfig` from the OCI image
   config (Entrypoint, Cmd, Env, WorkingDir), applying `WithInitOverride` if
   set. Writes the JSON file to `/.krun_config.json` in the rootfs.

5. **Start networking** -- Calls `net.Provider.Start()` which launches gvproxy
   (or a custom provider), waits for the Unix socket to be ready, and returns.

6. **Spawn runner** -- Serializes `runner.Config` as JSON and spawns
   `propolis-runner` as a detached subprocess (`setsid` for new session). The
   runner is located by searching: explicit path, system PATH, then next to
   the calling executable.

7. **Post-boot hooks** -- Runs caller-provided `PostBootHook` functions. If
   any hook fails, the VM is stopped and the error is returned.

### Runner Side (propolis-runner)

The runner binary (`runner/cmd/propolis-runner/main.go`) is intentionally
minimal. It is a thin translation layer between JSON config and the libkrun
C API:

1. Parse the JSON config from `os.Args[1]`
2. Validate: rootfs path exists and is a directory, vCPUs > 0, RAM > 0
3. Create a libkrun context via `krun.CreateContext()`
4. Configure vCPUs and RAM via `SetVMConfig()`
5. Set the root filesystem via `SetRoot()`
6. Add networking via `AddNetUnixStream()` (if socket path provided)
7. Add virtio-fs mounts via `AddVirtioFS()` (for each mount)
8. Set console output via `SetConsoleOutput()` (if log path provided)
9. Call `krun_start_enter()` which takes over the process

The runner does NOT call `SetExec()`. Instead, libkrun's built-in init process
(PID 1 in the guest) reads `/.krun_config.json` from the rootfs to determine
what program to execute. This is the same mechanism used by krunvm.

## OCI Image Pipeline

The pipeline converts an OCI container image into a booted microVM. Each step
includes security measures where applicable.

```
Step 1: PULL
  crane.Pull(imageRef) with context support
  Supports Docker Hub, GHCR, quay.io, private registries
  Uses ~/.docker/config.json for authentication
       |
Step 2: DIGEST
  img.Digest() --> manifest digest (sha256:...)
  Used as content-addressable cache key
       |
Step 3: CACHE CHECK
  cache.Get(digest) --> check if directory exists
  Hit?  --> return cached rootfs path + OCI config
  Miss? --> continue to extraction
       |
Step 4: FLATTEN
  mutate.Extract(img) --> single tar stream
  Merges all image layers into one unified filesystem
       |
Step 5: EXTRACT
  extractTar(reader, tmpDir) --> rootfs directory
  Security checks at this step:
    a. io.LimitedReader caps total extraction at 30 GiB
    b. sanitizeTarPath() rejects absolute paths and ".." traversal
    c. mkdirAllNoSymlink() refuses to follow symlinks when creating dirs
    d. validateNoSymlinkLeaf() prevents writing through symlinks
    e. Hardlink sources validated to stay within rootfs boundary
    f. Unsupported entry types (char/block devices, fifos) are skipped
       |
Step 6: CACHE STORE
  cache.Put(digest, tmpDir) --> atomic os.Rename to cache dir
  If another process already cached this digest, discard our extraction
       |
Step 7: ROOTFS HOOKS
  hook(rootfsPath, ociConfig) for each registered hook
  Runs in registration order; any error aborts the pipeline
       |
Step 8: KRUN CONFIG
  Write /.krun_config.json to rootfs:
  {
    "Cmd":        [...],     // from OCI or WithInitOverride
    "Env":        [...],     // PATH default + OCI env vars
    "WorkingDir": "/"        // from OCI or default "/"
  }
       |
Step 9: NETWORKING
  gvproxy.Start() or custom provider
  Writes gvproxy.yaml config, launches process, polls for socket
       |
Step 10: SPAWN
  runner.Spawn() --> propolis-runner subprocess
  Detached (setsid), stdout/stderr redirected to vm.log
       |
Step 11: POST-BOOT
  hook(ctx, vm) for each registered hook
  Common: SSH wait, config push, health check
```

## Image Caching

Images are cached by manifest digest under the data directory:

```
~/.config/propolis/cache/
    sha256-abc123def456.../    <-- extracted rootfs for this digest
    sha256-789012345678.../    <-- another cached image
```

### Cache Key

The cache key is the manifest digest (e.g., `sha256:abc123...`). The colon is
replaced with a hyphen for filesystem safety: `sha256-abc123...`.

### Cache Lookup

`cache.Get(digest)` checks if the directory exists via `os.Stat()`. If it
exists and is a directory, the cache hit returns the path.

### Cache Store

`cache.Put(digest, tmpDir)` uses `os.Rename()` for atomicity. If two
concurrent pulls for the same image race:
1. Both extract to separate temporary directories
2. The first to call `Rename` succeeds
3. The second detects the destination already exists and discards its extraction
   via `os.RemoveAll()`

This ensures no partial writes and no corruption from concurrent access.

### Cache Directory

The cache directory defaults to `~/.config/propolis/cache/`. It can be
customized via `WithDataDir()` (which sets the cache under `$dataDir/cache/`)
or directly via `WithImageCache(image.NewCache("/custom/path"))`.

## .krun_config.json

libkrun's built-in init process reads `/.krun_config.json` from the root of
the guest filesystem to determine what program to execute. propolis constructs
this file from the OCI image config with optional overrides.

### Format

```json
{
  "Cmd": ["/bin/sh", "-c", "echo hello"],
  "Env": [
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME=/root"
  ],
  "WorkingDir": "/"
}
```

### Field Resolution

| Field | Source | Override |
|-------|--------|---------|
| `Cmd` | OCI Entrypoint + Cmd concatenated | `WithInitOverride(cmd...)` replaces entirely |
| `Env` | Default `PATH` + OCI image `Env` | None (extend via rootfs hook) |
| `WorkingDir` | OCI `WorkingDir`, or `/` if unset | None |

### How libkrun Uses It

1. libkrun's init process starts as PID 1 in the guest
2. It reads `/.krun_config.json`
3. It sets the environment variables from `Env`
4. It changes to `WorkingDir`
5. It executes `Cmd[0]` with `Cmd[1:]` as arguments

This is the same mechanism used by krunvm and podman machine.

## Networking

propolis uses gvproxy for host-guest networking by default. The networking
layer is abstracted behind the `net.Provider` interface, allowing alternative
implementations.

### Network Topology

```
+---------------------------------------------------+
|                   Host Machine                     |
|                                                    |
|  +-----------+     Unix socket     +-----------+   |
|  |  gvproxy  |---(SOCK_STREAM)--->|  libkrun  |   |
|  |           |   4-byte BE len    |  virtio-  |   |
|  | Gateway:  |   prefix frames    |  net      |   |
|  | 192.168.  |                    |           |   |
|  | 127.1     |                    +-----------+   |
|  |           |                         |          |
|  | DHCP      |                    +----v------+   |
|  | DNS       |                    | Guest VM  |   |
|  | Port fwd  |                    |           |   |
|  +-----------+                    | eth0:     |   |
|       |                           | 192.168.  |   |
|       |  Port forwards:           | 127.2     |   |
|       |  localhost:8080            |           |   |
|       +-----> guest:80            +-----------+   |
|       |  localhost:2222                           |
|       +-----> guest:22                            |
+---------------------------------------------------+
```

### gvproxy Configuration

The `net/gvproxy` package writes a YAML config file and launches gvproxy
with `-config` pointing at it:

```yaml
interfaces:
  qemu: unix:///path/to/gvproxy.sock
stack:
  forwards:
    "127.0.0.1:8080": "192.168.127.2:80"
    "127.0.0.1:2222": "192.168.127.2:22"
```

We use `interfaces.qemu` because both gvproxy's QEMU transport and libkrun's
`krun_add_net_unixstream` use identical wire format: `SOCK_STREAM` with 4-byte
big-endian length prefix per Ethernet frame. The vfkit transport
(`unixgram`) is macOS-only in gvproxy, but the QEMU transport works on all
platforms.

### Network Details

| Property | Value |
|----------|-------|
| Gateway | 192.168.127.1 (gvproxy) |
| Guest IP | 192.168.127.2 (DHCP assigned) |
| Subnet | 192.168.127.0/24 |
| Socket type | Unix domain, SOCK_STREAM |
| Wire format | 4-byte big-endian length prefix + Ethernet frame |
| DHCP | Built into gvproxy |
| DNS | Built into gvproxy |
| Port forwarding | TCP, host-to-guest only |

### gvproxy Lifecycle

1. `Start()` removes any stale socket file from a previous run
2. Writes the YAML config with socket path and port forwards
3. Launches gvproxy with `-config` as a detached process (`setsid`)
4. Polls for the socket file to appear (100ms intervals, 10s timeout)
5. Returns once the socket is ready
6. If gvproxy exits prematurely, returns an error with the exit code

`Stop()` sends SIGTERM, falls back to SIGKILL, reaps the process, and
cleans up the socket file.

### The net.Provider Interface

```go
type Provider interface {
    // Start launches the network provider. Must block until ready.
    Start(ctx context.Context, cfg Config) error

    // SocketPath returns the Unix socket for virtio-net.
    SocketPath() string

    // PID returns the provider process ID, or 0 if not running.
    PID() int

    // Stop terminates the provider and cleans up.
    Stop()
}
```

`Config` contains:
- `LogDir` -- directory for log files
- `Forwards` -- slice of `PortForward{Host, Guest}` for TCP forwarding

To replace gvproxy with a different networking backend (e.g., passt, slirp4netns,
a custom bridge), implement this interface and pass it via
`propolis.WithNetProvider()`. The `SocketPath()` return value is passed to the
runner as the Unix socket path for `krun_add_net_unixstream`.

## Extension Points

```
                    propolis.Run()
                         |
            +------------+------------+
            |                         |
     preflight.Checker          net.Provider
     (KVM, ports, resources,    (gvproxy, custom)
      disk space, custom)             |
            |                         |
            v                         v
      Pull & Extract            Start networking
            |                         |
            v                         |
      RootFSHook(s)                   |
      (inject files, SSH keys,        |
       TLS certs, config)             |
            |                         |
            v                         v
      Write .krun_config.json   Socket ready
      (WithInitOverride to            |
       replace OCI CMD)               |
            |                         |
            +------------+------------+
                         |
                   Spawn runner
                         |
                         v
                  PostBootHook(s)
                  (SSH wait, config push,
                   health checks, service mesh)
```

### Preflight Checks

Inject validation before any work begins:
```go
propolis.WithPreflightChecks(check1, check2)
```

### Rootfs Hooks

Modify the extracted filesystem before boot:
```go
propolis.WithRootFSHook(func(rootfs string, cfg *image.OCIConfig) error {
    // Write files, install keys, modify configs
    return nil
})
```

### Init Override

Replace the OCI ENTRYPOINT/CMD:
```go
propolis.WithInitOverride("/sbin/my-init", "--flag")
```

### Network Provider

Replace gvproxy with a custom networking backend:
```go
propolis.WithNetProvider(myProvider)
```

### Post-Boot Hooks

Run logic after the VM process is confirmed alive:
```go
propolis.WithPostBoot(func(ctx context.Context, vm *propolis.VM) error {
    // Wait for SSH, push config, verify health
    return nil
})
```

## Preflight Check System

The `preflight` package provides an extensible system for running pre-boot
verification checks.

### Core Types

```go
// Check represents a single preflight verification.
type Check struct {
    Name        string                          // Short identifier
    Description string                          // Human-readable description
    Run         func(ctx context.Context) error // Nil on success, error on failure
    Required    bool                            // true = fatal, false = warning
}

// Checker runs preflight checks before VM creation.
type Checker interface {
    RunAll(ctx context.Context) error   // Run all checks, return error if any required fail
    Register(check Check)              // Add a check
}
```

### Built-in Checks

| Check | Platform | Required | Description |
|-------|----------|----------|-------------|
| `kvm` | Linux | Yes | Verifies `/dev/kvm` exists, is a character device, and is read/write accessible. Error messages include remediation hints (modprobe commands, usermod). |
| `disk-space` | Linux | No | Verifies at least 2.0 GB free disk space on the data directory filesystem. Walks up the directory tree to find an existing ancestor if the dir does not yet exist. |
| `resources` | Linux | No | Verifies the host has at least 1 CPU core and 1.0 GiB RAM. |
| `ports` | All | Yes | Verifies requested host ports are available for binding. Uses `ss` on Linux to identify the process holding a port. |

On macOS, the `kvm`, `disk-space`, and `resources` checks are either no-ops
or not registered. Hypervisor.framework is assumed available on Apple Silicon.

### Execution

`RunAll()` executes checks in registration order. Required check failures are
collected into a combined error. Non-required failures are logged as warnings
via `slog.Warn` but do not prevent the pipeline from proceeding.

### Adding Custom Checks

Pass checks via `WithPreflightChecks()`:

```go
propolis.Run(ctx, ref,
    propolis.WithPreflightChecks(
        preflight.PortCheck(8080, 2222),
        preflight.Check{
            Name:     "my-check",
            Description: "Check something",
            Run:      func(ctx context.Context) error { return nil },
            Required: true,
        },
    ),
)
```

Custom checks are appended to (not replacing) the built-in platform defaults.

To replace the entire preflight checker (e.g., when the caller manages its own):
```go
propolis.WithPreflightChecker(preflight.NewEmpty())
```

## State Management

The `state` package provides persistent VM state with file-based locking.

### Directory Layout

```
~/.config/propolis/           (or $PROPOLIS_DATA_DIR, or WithDataDir path)
    state.json                <-- VM state (atomic JSON)
    state.lock                <-- flock for exclusive access
    cache/
        sha256-abc123.../     <-- cached rootfs by digest
        sha256-def456.../
    console.log               <-- guest console output (kernel, init)
    vm.log                    <-- propolis-runner stdout/stderr
    gvproxy.sock              <-- gvproxy Unix domain socket
    gvproxy.yaml              <-- gvproxy config (generated)
    gvproxy.log               <-- gvproxy stdout/stderr
```

### State JSON Schema

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

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | State file format version (currently 1) |
| `active` | bool | Whether the VM is currently running |
| `name` | string | VM name |
| `image` | string | OCI image reference |
| `cpus` | uint32 | Number of vCPUs |
| `memory_mb` | uint32 | RAM in MiB |
| `pid` | int | Runner process ID (0 if not running) |
| `net_provider_pid` | int | Network provider PID (0 if not running) |
| `created_at` | RFC 3339 | When the state was first created |

### Locking Protocol

The `state.Manager` provides atomic load-and-lock semantics:

1. `LoadAndLock(ctx)` acquires an exclusive `flock` on `state.lock`
2. Reads and parses `state.json` (or returns a default State if the file
   does not exist)
3. Returns a `LockedState` that holds the lock

The lock is held until `LockedState.Release()` is called. Callers should
use `defer` to ensure the lock is always released:

```go
mgr := state.NewManager(dataDir)
ls, err := mgr.LoadAndLock(ctx)
if err != nil {
    return err
}
defer ls.Release()

ls.State.Active = true
ls.State.PID = proc.PID
return ls.Save()
```

`LoadAndLockWithRetry(ctx, timeout)` wraps `LoadAndLock` with a retry loop
for cases where another process may hold the lock temporarily.

`Load()` reads the state without locking (read-only access).

### Atomic Writes

`LockedState.Save()` ensures crash safety:

1. Marshals the state to JSON with indentation
2. Writes to a temporary file in the same directory (`state-*.json.tmp`)
3. Calls `os.Rename()` to atomically replace `state.json`

If a crash occurs during write, either the old state remains intact or the
new state is fully written -- never a partial file. The `flock` ensures only
one process writes at a time.

## Security Model

### Guest-VMM Trust Boundary

libkrun runs the guest and VMM in the same process and security context. From
the libkrun documentation: the microVM provides hardware-level isolation via
KVM (Linux) or Hypervisor.framework (macOS), but the VMM itself is not
sandboxed from the host process.

This means:
- The VM provides stronger isolation than containers (hardware MMU separation)
- The VMM process has the same privileges as the user running it
- A guest escape would land in the VMM process context
- This is the same model used by krunvm and crun+libkrun

For security-critical deployments, combine propolis with additional host-level
sandboxing (seccomp, SELinux, namespaces) around the runner process.

### Tar Extraction Defenses

The `image/pull.go` file implements multiple layers of defense against
malicious OCI image layers:

**1. Path Traversal Prevention (`sanitizeTarPath`)**

Every tar entry name is cleaned and validated:
- `filepath.Clean()` removes `.` and `..` components
- Absolute paths in tar entries are rejected
- The resolved path is verified to be under the destination directory via
  `filepath.Rel()` and prefix checking

**2. Symlink Traversal Prevention (`mkdirAllNoSymlink`)**

When creating parent directories for extraction:
- Directories are created one component at a time
- Each existing component is checked with `os.Lstat()` (not `os.Stat()`,
  which would follow symlinks)
- If any component is a symlink, extraction is refused
- This prevents a crafted symlink earlier in the archive from redirecting
  later entries outside the rootfs

**3. Symlink Leaf Validation (`validateNoSymlinkLeaf`)**

Before writing a regular file:
- The target path is checked with `os.Lstat()`
- If the target is a symlink, writing is refused
- If the target is a directory, overwriting is refused

**4. Symlink Target Validation (`extractSymlink`)**

When creating symlinks:
- Absolute symlink targets are resolved relative to the rootfs and checked
  to stay within bounds
- Relative symlink targets are resolved from the symlink's parent directory
  and checked to stay within bounds

**5. Hardlink Boundary Enforcement (`extractHardlink`)**

Hard links are validated to ensure both source and target remain within the
rootfs directory. A hardlink that points outside the rootfs is rejected.

**6. Decompression Bomb Limit**

The tar reader is wrapped in `io.LimitedReader` with a 30 GiB limit. If the
extracted data exceeds this limit, extraction is aborted with a descriptive
error. This prevents resource exhaustion from maliciously compressed archives.

**7. Entry Type Filtering**

Unsupported tar entry types (character devices, block devices, fifos) are
silently skipped. These are not needed for a libkrun rootfs and could pose
security risks if created.

### Process Identity Verification

When managing VM lifecycle, propolis verifies process identity before sending
signals:

- `runner.Process.IsAlive()` sends signal 0 to the PID via
  `process.Signal(syscall.Signal(0))`. This is a no-op signal that only
  succeeds if the process exists and the caller has permission to signal it.
- `Stop()` checks `IsAlive()` before sending SIGTERM, and checks again during
  the poll loop before sending SIGKILL.
- The `isNoSuchProcess()` helper handles the `ESRCH` error (process not found)
  gracefully.

This prevents sending signals to unrelated processes if the PID has been
reused after the VM exited.

### File Permissions

- State directory: 0700 (owner only)
- State lock file: created by flock
- SSH private keys: 0600 (owner read/write only)
- SSH public keys: 0644 (world readable)
- VM log files: 0600 (owner only)
- Cache directories: 0700 (owner only)

## SSH Utilities

The `ssh` package provides two capabilities used by consumers like
toolhive-appliance:

### Key Generation

`GenerateKeyPair(keyDir)` creates an ECDSA P-256 SSH key pair:

- Private key: `keyDir/id_ecdsa` with 0600 permissions, PEM-encoded EC key
- Public key: `keyDir/id_ecdsa.pub` with 0644 permissions, OpenSSH
  authorized_keys format

If the key files already exist, they are overwritten.

`GetPublicKeyContent(publicKeyPath)` reads the public key file and returns
its content as a string for inclusion in authorized_keys.

### SSH Client

`ssh.Client` wraps `golang.org/x/crypto/ssh` with convenience methods:

| Method | Description |
|--------|-------------|
| `Run(ctx, cmd)` | Execute a command, return combined stdout+stderr |
| `RunSudo(ctx, cmd)` | Execute via `doas` (used in Alpine-based VMs) |
| `RunStream(ctx, cmd, stdout, stderr)` | Execute with streaming I/O |
| `CopyTo(ctx, local, remote, mode)` | Upload a file via `cat` over SSH |
| `CopyFrom(ctx, remote, local)` | Download a file via `cat` over SSH |
| `WaitForReady(ctx)` | Poll SSH at 2s intervals until connection succeeds |

`ShellEscape(s)` wraps a string in single quotes with proper escaping for
safe use in shell commands.

### WaitForReady Pattern

The standard post-boot hook pattern uses `WaitForReady`:

```go
propolis.WithPostBoot(func(ctx context.Context, vm *propolis.VM) error {
    client := ssh.NewClient("127.0.0.1", 2222, "root", keyPath)
    return client.WaitForReady(ctx)
})
```

`WaitForReady` polls every 2 seconds, attempting a full SSH connection and
running `true` as a trivial command. It returns when the connection succeeds
or the context is cancelled. Connection timeout per attempt is 10 seconds.

**Security note:** The SSH client uses `InsecureIgnoreHostKey()` for host key
verification. This is acceptable because we trust the VM we just created -- it
was booted from an image we pulled and configured.

## Relationship to toolhive-appliance

[toolhive-appliance](https://github.com/stacklok/toolhive-appliance) is the
primary consumer of propolis. It uses the extension points to build a complete
appliance experience:

| Extension Point | toolhive-appliance Usage |
|-----------------|--------------------------|
| `WithName` | Names the VM "toolhive-appliance" |
| `WithInitOverride` | Injects `toolhive-init.sh` that starts k3s and services |
| `WithRootFSHook` | Writes SSH keys, TLS certificates, configuration files |
| `WithPostBoot` | Waits for SSH, pushes runtime config, syncs kubeconfig, verifies health |
| `WithPreflightChecks` | Validates KVM, disk space, connectivity |
| `WithVirtioFS` | Shares host directories for data persistence |
| `WithDataDir` | Uses `~/.config/toolhive-appliance/` |
| `WithRootFSPath` | Uses pre-built rootfs (skips OCI image pull) |
| `WithPreflightChecker` | Replaces default preflight with empty checker (appliance has its own) |
| `WithRunnerPath` | Points at the embedded `propolis-runner` binary |
| `WithLibDir` | Points at bundled libkrun/libkrunfw libraries |
| `WithPorts` | Forwards HTTP (8080), HTTPS (8443), k8s API (6443), SSH (2222) |
| `WithCPUs` / `WithMemory` | Configures VM resources per user settings |

### Migration Path

propolis was extracted from toolhive-appliance to provide a reusable library.
If you are building a similar appliance:

1. Import `github.com/stacklok/propolis` as a library
2. Build your own init script for the guest
3. Use `WithRootFSHook` to inject your configuration
4. Use `WithPostBoot` for your post-boot orchestration
5. Build your own CLI around `propolis.Run()`

The propolis library handles the OCI-to-microVM pipeline. You provide the
domain-specific logic via hooks and options.
