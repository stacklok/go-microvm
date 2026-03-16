# Troubleshooting

Common issues when using go-microvm and how to resolve them.

## VM Fails to Start

### KVM not available (Linux)

```bash
# Check KVM device exists
ls -la /dev/kvm

# If missing, load the module
sudo modprobe kvm
sudo modprobe kvm_intel  # or kvm_amd

# Check permissions
groups | grep -q kvm || sudo usermod -aG kvm $USER
# Log out and back in after adding to group
```

### Hypervisor.framework not available (macOS)

```bash
sysctl kern.hv_support
# Must return 1. If 0, Apple Silicon with Hypervisor.framework is required.
```

### Code signing required (macOS)

If go-microvm-runner crashes immediately with `EXC_BAD_ACCESS`, it needs the
hypervisor entitlement. See [docs/MACOS.md](MACOS.md).

## Log Files

go-microvm writes log files to the data directory
(`~/.config/go-microvm/` by default, or the path set via `WithDataDir()`):

| File | Contents |
|------|----------|
| `console.log` | Guest console output (kernel messages, init script) |
| `vm.log` | go-microvm-runner stdout/stderr (libkrun errors) |

Networking logs are emitted via `log/slog` and appear in the application's
structured logging output rather than a separate file.

```bash
# Check for guest-side errors (kernel, init script)
cat ~/.config/go-microvm/console.log

# Check for host-side runner errors
cat ~/.config/go-microvm/vm.log
```

## Port Conflicts

If `Run()` fails with a port availability error:

```bash
# Find what's using the port (Linux)
ss -tlnp | grep ':8080'

# Find what's using the port (macOS)
lsof -iTCP:8080 -sTCP:LISTEN
```

## Networking Issues

### Guest has no network

The guest should get IP `192.168.127.2` via DHCP from the in-process
VirtualNetwork. Check `console.log` for DHCP client output.

If the guest has no network, verify that the networking provider started
successfully by checking the application's log output for errors from
`net.Provider.Start()`.

## Runner Binary Not Found

go-microvm searches for `go-microvm-runner` in this order:
1. Explicit path via `libkrun.WithRunnerPath()` (passed to `libkrun.NewBackend()`)
2. System `$PATH`
3. Next to the calling executable

```bash
# Check if it's in PATH
which go-microvm-runner

# Build it (requires system libkrun-devel)
cd go-microvm && task build-dev
```

## Resource Limits

### vCPU limit

The stock libkrunfw kernel is compiled with `CONFIG_NR_CPUS=8`, limiting
guests to 8 vCPUs. Requesting more will fail at `SetVMConfig()`.

### Memory

There is no hard memory limit from libkrun. The practical limit is
available host RAM. go-microvm defaults to 512 MiB.

## Licensing

libkrunfw bundles a Linux kernel compiled with the `kvm` guest patches.
The kernel is licensed under GPL-2.0-only. If you distribute a binary
that embeds libkrunfw, you must provide the corresponding kernel source
(or a written offer to provide it). See the
[libkrunfw repository](https://github.com/containers/libkrunfw) for
source availability.
