# Troubleshooting

Common issues when using propolis and how to resolve them.

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

If propolis-runner crashes immediately with `EXC_BAD_ACCESS`, it needs the
hypervisor entitlement. See [docs/MACOS.md](MACOS.md).

## Log Files

propolis writes several log files to the data directory
(`~/.config/propolis/` by default, or the path set via `WithDataDir()`):

| File | Contents |
|------|----------|
| `console.log` | Guest console output (kernel messages, init script) |
| `vm.log` | propolis-runner stdout/stderr (libkrun errors) |
| `gvproxy.log` | gvproxy networking daemon output |

```bash
# Check for guest-side errors (kernel, init script)
cat ~/.config/propolis/console.log

# Check for host-side runner errors
cat ~/.config/propolis/vm.log

# Check for networking errors
cat ~/.config/propolis/gvproxy.log
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

### Stale gvproxy socket

If gvproxy fails to start with a socket error, a stale socket from a
previous run may exist. propolis cleans stale sockets automatically, but
if the data directory was corrupted:

```bash
rm ~/.config/propolis/gvproxy.sock
```

### Guest has no network

Check that gvproxy is running and the socket exists:

```bash
ls -la ~/.config/propolis/gvproxy.sock
ps aux | grep gvproxy
```

The guest should get IP `192.168.127.2` via DHCP from gvproxy. Check
`console.log` for DHCP client output.

## Runner Binary Not Found

propolis searches for `propolis-runner` in this order:
1. Explicit path via `WithRunnerPath()`
2. System `$PATH`
3. Next to the calling executable

```bash
# Check if it's in PATH
which propolis-runner

# Build it (requires system libkrun-devel)
cd propolis && task build-dev
```

## Resource Limits

### vCPU limit

The stock libkrunfw kernel is compiled with `CONFIG_NR_CPUS=8`, limiting
guests to 8 vCPUs. Requesting more will fail at `SetVMConfig()`.

### Memory

There is no hard memory limit from libkrun. The practical limit is
available host RAM. propolis defaults to 512 MiB.

## Licensing

libkrunfw bundles a Linux kernel compiled with the `kvm` guest patches.
The kernel is licensed under GPL-2.0-only. If you distribute a binary
that embeds libkrunfw, you must provide the corresponding kernel source
(or a written offer to provide it). See the
[libkrunfw repository](https://github.com/containers/libkrunfw) for
source availability.
