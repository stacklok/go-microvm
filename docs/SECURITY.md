# Security Model

This document describes the security properties, trust boundaries, and
hardening recommendations for propolis.

## Table of Contents

- [Trust Boundaries](#trust-boundaries)
- [Guest-VMM Trust Boundary](#guest-vmm-trust-boundary)
- [Networking Trust Boundary](#networking-trust-boundary)
- [Guest Escape Blast Radius](#guest-escape-blast-radius)
- [Hardening Recommendations](#hardening-recommendations)
- [Guest Hardening](#guest-hardening)
- [Egress Policy Security Model](#egress-policy-security-model)
- [Tar Extraction Defenses](#tar-extraction-defenses)
- [Process Identity Verification](#process-identity-verification)
- [File Permissions](#file-permissions)
- [SSH Client Security](#ssh-client-security)

## Trust Boundaries

propolis has two trust boundaries:

```
                    Trust boundary 1: KVM/HVF
                    (hardware isolation)
                           |
+-------------------------+|+------------------------------------------+
|       Guest VM          |||       propolis-runner                     |
|    (untrusted code)     ||| +------------------+ +------------------+|
|                         ||| | libkrun VMM      | | VirtualNetwork   ||
|  Runs user workload     ||| | (virtio devices, | | (gvisor-tap-vsock||
|  inside hardware-       ||| |  VM supervisor)  | |  DHCP, DNS, NAT, ||
|  isolated VM            ||| |                  | |  port forwarding)||
|                         ||| +------------------+ +------------------+|
+-------------------------+|+------------------------------------------+
                           |           |
                           |    Trust boundary 2: process isolation
                           |    (OS-level, user privileges)
                           |           |
                    +------+-----------+------+
                    |      Host OS            |
                    |  (caller's user context)|
                    +-------------------------+
```

## Guest-VMM Trust Boundary

libkrun runs the guest and VMM in the same process. The microVM provides
hardware-level isolation via KVM (Linux) or Hypervisor.framework (macOS),
but the VMM itself is not sandboxed from the host process.

This means:
- The VM provides stronger isolation than containers (hardware MMU separation)
- The VMM process has the same privileges as the user running it
- A guest escape would land in the VMM process context
- This is the same model used by krunvm and crun+libkrun

## Networking Trust Boundary

The location of the VirtualNetwork depends on the networking mode:

- **Default (runner-side)**: The runner process hosts both the libkrun VMM
  and the VirtualNetwork in the same OS process. The network stack's
  lifecycle is tied to the VM's lifetime.
- **Hosted (caller-side)**: The VirtualNetwork runs in the caller's process
  via `net/hosted.Provider`. The runner connects over a Unix socket.

### What shares the runner process (default mode)

| Component | Role |
|-----------|------|
| libkrun VMM | VM supervisor, virtio device emulation |
| VirtualNetwork | Userspace TCP/IP stack (gVisor netstack) |
| DHCP server | Assigns guest IP (192.168.127.2) |
| DNS server | Resolves names for the guest |
| Port forward listeners | TCP listeners on 127.0.0.1 for host-to-guest forwarding |

### What shares the runner process (hosted mode)

| Component | Role |
|-----------|------|
| libkrun VMM | VM supervisor, virtio device emulation |

In hosted mode, the VirtualNetwork, DHCP, DNS, port forwards, and any
HTTP services run in the caller's process instead. A guest escape still
lands in the runner process, but the network stack is in a separate
process, providing better isolation.

### Why the default mode is acceptable

1. **Single-VM model.** There is exactly one guest per runner process.
   The network stack serves only that guest. There is no cross-tenant
   risk because there is no second tenant.

2. **Port forwards are localhost-only.** All port forward listeners bind
   to `127.0.0.1`, hardcoded in the runner. There is no configuration
   path to bind to `0.0.0.0` or an external interface.

3. **The VMM was already unsandboxed.** A guest escape already gives the
   attacker full user-level host access (the runner's UID). Adding the
   network stack to the same process does not meaningfully widen this --
   the attacker could already open sockets and access the network.

4. **No secrets in the network stack.** The VirtualNetwork does not hold
   TLS keys, credentials, or tokens. Port forwards are simple TCP
   proxies. The DHCP/DNS servers have no auth material.

## Guest Escape Blast Radius

If an attacker exploits a KVM/HVF vulnerability or a libkrun bug to
escape the guest, they land in the runner process with:

| Capability | Default mode | Hosted mode |
|-----------|------|------|
| Runner's UID privileges | Yes | Yes |
| Rootfs directory access | Yes | Yes |
| Console/VM log files | Yes | Yes |
| VirtualNetwork goroutines | Yes | No (separate process) |
| Port forward listeners on 127.0.0.1 | Yes | No (separate process) |
| DHCP/DNS servers | Yes | No (separate process) |
| Socketpair fd to krun | Yes (inject/modify frames) | Unix socket (inject/modify frames) |

What they do NOT get:
- Root privileges (unless the runner was run as root)
- Access to other users' processes or files
- Kernel-level access (the escape lands in userspace)
- Network listeners on external interfaces

In hosted mode, the network stack is in the caller's process, so a guest
escape does not directly compromise it. This provides better isolation for
security-sensitive deployments.

### Where this would be a higher concern

The collapsed trust boundary (default mode) would matter more if:

- **Multiple VMs shared a VirtualNetwork** (multi-tenant): one VM could
  sniff or poison another's traffic. propolis does not support this.
- **The network stack held secrets** (TLS termination, auth tokens):
  a guest escape would expose them. propolis port forwards are plain TCP.
- **The network stack ran with higher privileges** than the VMM: not the
  case here, both share the same process and UID.

For deployments where these concerns apply, use the hosted provider
(`net/hosted.Provider`) which moves the network stack to the caller's
process, providing natural process-level separation.

## Hardening Recommendations

For security-critical deployments, layer additional isolation around
the runner process:

### seccomp (recommended)

Restrict the runner's syscalls to only what libkrun and gvisor-tap-vsock
need. This is the highest-impact hardening measure. After a guest escape,
the attacker lands in a seccomp jail that limits what syscalls they can
make.

```
Runner process
  └── seccomp filter: allow only needed syscalls
       ├── ioctl (KVM/HVF)
       ├── read/write/close (fd operations)
       ├── mmap/mprotect (memory management)
       ├── socket/bind/listen/accept (networking)
       ├── epoll/poll (event loop)
       └── deny everything else
```

### Linux namespaces

Run the runner in restricted namespaces:

- **User namespace**: map the runner's UID to an unprivileged range
- **Mount namespace**: limit filesystem visibility to rootfs + data dir
- **Network namespace**: not applicable (the network stack needs host
  access for port forwarding), but PID namespace limits process visibility

### SELinux / AppArmor

Confine the runner to a policy that restricts:
- File access to the data directory and rootfs only
- Network access to localhost port forwards only
- No access to other users' home directories or system paths

### Process separation (defense in depth)

Use the hosted networking provider (`net/hosted.Provider`) to move the
network stack out of the runner process. This achieves process-level
separation without a custom helper binary:

```
propolis-runner (VMM only)
    └── Unix socket → hosted provider in caller's process
caller's process (network stack)
    └── hosted.Provider → VirtualNetwork + HTTP services
```

This is not the default because it requires the caller's process to
remain alive for networking to function. For the simplest deployments,
the default runner-side networking ties the network stack to the VM's
lifetime with no extra coordination.

## Guest Hardening

The `guest/harden` package provides reusable kernel and capability
hardening for microVM init processes. It is guest-side code
(`//go:build linux`) with no CGO or krun dependencies.

### Recommended usage

Call the hardening functions in your guest init boot sequence:

1. Mount `/proc` and `/sys` first (sysctls need procfs).
2. Call `harden.KernelDefaults(logger)` to apply sysctls.
3. Perform all privileged operations (mounts, network config, chown).
4. Call `harden.DropBoundingCaps(keep...)` as the last privileged step.

### Kernel sysctls

`KernelDefaults` applies the following sysctls. Each is set
independently; individual failures are logged as warnings rather than
aborting boot, because not all kernels support every sysctl.

| Sysctl | Value | Purpose |
|--------|-------|---------|
| `kernel.kptr_restrict` | `2` | Hide kernel pointers from all users. Prevents information leaks that aid exploit development. |
| `kernel.dmesg_restrict` | `1` | Restrict `dmesg` to privileged users. Prevents unprivileged processes from reading kernel log messages that may contain sensitive addresses or operations. |
| `kernel.unprivileged_bpf_disabled` | `1` | Disable unprivileged BPF. Prevents unprivileged users from loading BPF programs, which have historically been a source of kernel privilege escalation vulnerabilities. |
| `kernel.perf_event_paranoid` | `3` | Disallow all perf events for unprivileged users. Prevents unprivileged access to performance counters, which can be used for side-channel attacks. |
| `kernel.yama.ptrace_scope` | `2` | Restrict ptrace to `CAP_SYS_PTRACE` holders. Prevents unprivileged processes from attaching to other processes to inspect memory or inject code. |
| `net.core.bpf_jit_harden` | `2` | Harden BPF JIT against spraying attacks. Forces constant blinding and disables JIT kallsyms exposure. |
| `kernel.sysrq` | `0` | Disable magic SysRq key. Prevents unprivileged users from triggering kernel debugging and recovery commands. |

### Capability bounding set

`DropBoundingCaps(keep...)` drops all Linux capabilities from the
bounding set except those explicitly listed. This limits what
capabilities child processes can acquire, even through setuid binaries
or file capabilities.

For a typical SSH-based guest, the minimal keep set is:

| Capability | Number | Reason |
|-----------|--------|--------|
| `CAP_SETUID` | 7 | sshd credential switching to sandbox user |
| `CAP_SETGID` | 6 | sshd group switching |
| `CAP_NET_BIND_SERVICE` | 10 | Binding port 22 (privileged port) |

### Process privilege restriction

`SetNoNewPrivs()` sets the `PR_SET_NO_NEW_PRIVS` bit on the calling
process. Once set, the process and all descendants (via fork/exec)
cannot gain new privileges through `execve` — setuid binaries run
without elevation and file capabilities are ignored.

This is intended to be called after all privileged operations are
complete (mounts, network config, credential setup, capability
dropping). Consumers that spawn child processes via `os/exec` inherit
the bit automatically; consumers that need to set it on the calling
process itself (e.g., an init that doesn't use `os/exec`) can call
`SetNoNewPrivs()` directly.

Note: `no_new_privs` does not affect `setresuid`/`setresgid` syscalls
used by Go's `SysProcAttr.Credential` — credential switching for SSH
sessions continues to work after the bit is set.

### Filesystem hardening

Consumers should lock down `/root/` (mode `0700`) after completing
initial setup so the sandbox user cannot read root's home directory
contents (bootstrap config, debug logs, credentials). This is not
performed by the `harden` package itself but is a recommended consumer
practice — see apiary's `lockdownRoot()` for an example.

### Threat model

These hardening measures are defense-in-depth for the guest
environment. An attacker who has compromised the guest workload would
need a hypervisor escape to reach the host; however, guest hardening:

- Raises the bar for local privilege escalation within the guest
- Reduces information available for exploit development (kernel pointers, dmesg)
- Limits the attack surface of dangerous subsystems (BPF)
- Constrains what a compromised process can do even with root inside the guest

## Egress Policy Security Model

The DNS-based egress policy (`WithEgressPolicy()`) restricts VM outbound
connections to a set of allowed hostnames. It operates at the relay level,
intercepting DNS traffic between the VM and the VirtualNetwork.

### Threat Model

The egress policy prevents a compromised or untrusted VM from:

- Exfiltrating data to arbitrary external hosts
- Communicating with command-and-control servers
- Scanning or connecting to internal network resources

### How It Works

1. DNS queries for non-allowed hostnames receive NXDOMAIN responses
   directly from the relay — the query never reaches the DNS server.
2. DNS responses for allowed hostnames are snooped to extract A-record IPs.
   These IPs become temporary firewall rules with TTLs matching the DNS
   record TTLs (minimum 60 seconds).
3. All other egress traffic is denied by the default-deny firewall policy.
4. Implicit rules allow DNS to the gateway, DHCP, and ingress on
   port-forwarded ports.

### Bypass Vectors and Mitigations

| Vector | Mitigation |
|--------|------------|
| **Hardcoded IPs** | Default-deny blocks connections to IPs not learned from DNS. The VM cannot reach arbitrary IPs without first resolving them through the interceptor. |
| **DNS-over-HTTPS (DoH)** | HTTPS to DoH providers (e.g., 1.1.1.1, 8.8.8.8) is blocked by default-deny unless the DoH server hostname is in the allowlist. |
| **DNS-over-TLS (DoT)** | TCP port 853 is blocked by default-deny. |
| **IP-in-hostname** | The policy matches hostname strings, not resolved IPs. An attacker-controlled DNS server could return arbitrary IPs for an allowed hostname, but the attacker would need to control the DNS server the gateway uses. |
| **Tunneling over DNS** | DNS queries to allowed domains pass through, so DNS tunneling to an allowed domain is theoretically possible. This is a limitation of DNS-level filtering. |
| **TTL racing** | After a dynamic rule expires, the connection may survive via conntrack (if already established). This is by design — conntrack ensures established connections are not disrupted by TTL expiry. |

### What It Does NOT Protect Against

- **Established connection survival**: Once a connection is tracked by
  conntrack, it persists until the conntrack entry expires (5 minutes for
  TCP, 30 seconds for UDP), even if the dynamic rule has expired.
- **Same-subnet traffic**: Traffic within the virtual network subnet
  (192.168.127.0/24) is subject to the same firewall rules but does not
  typically involve DNS resolution.
- **IPv6**: AAAA records are not processed. IPv6 traffic is non-IPv4 and
  passes through the firewall unfiltered (same as ARP).

## Tar Extraction Defenses

When extracting OCI image layers, propolis applies multiple layers of
defense against malicious tar archives:

**Path traversal prevention.** Every tar entry name is cleaned via
`filepath.Clean()`, absolute paths are rejected, and the resolved path
is verified to stay under the destination directory.

**Symlink traversal prevention.** Directories are created one component
at a time. Each existing component is checked with `os.Lstat()` (not
`os.Stat()`, which would follow symlinks). If any component is a symlink,
extraction is refused.

**Symlink leaf validation.** Before writing a regular file, the target
path is checked with `os.Lstat()`. If the target is a symlink or a
directory, writing is refused.

**Symlink target validation.** Absolute symlink targets are resolved
relative to the rootfs and checked to stay within bounds. Relative
symlink targets are resolved from the parent directory.

**Hardlink boundary enforcement.** Hard links are validated to ensure
both source and target remain within the rootfs directory.

**Decompression bomb limit.** The tar reader is wrapped in
`io.LimitedReader` with a 30 GiB cap.

**Entry type filtering.** Character devices, block devices, and FIFOs
are silently skipped.

## Process Identity Verification

When managing VM lifecycle, propolis verifies process identity before
sending signals:

- `IsAlive()` sends signal 0 to the PID (no-op that verifies the
  process exists and the caller has permission to signal it)
- `Stop()` checks `IsAlive()` before SIGTERM, and checks again during
  the poll loop before SIGKILL
- The `isNoSuchProcess()` helper handles `ESRCH` gracefully

This prevents sending signals to unrelated processes if the PID has
been reused.

## File Permissions

| Resource | Mode | Description |
|----------|------|-------------|
| State directory | 0700 | Owner only |
| State lock file | flock | Exclusive access |
| SSH private keys | 0600 | Owner read/write |
| SSH public keys | 0644 | World readable |
| VM log files | 0600 | Owner only |
| Cache directories | 0700 | Owner only |
| Unix socket (vnet.sock) | 0700 dir | Protected by parent directory permissions |

## SSH Client Security

The SSH client uses `InsecureIgnoreHostKey()` for host key verification.
This is acceptable because the client only connects to VMs that propolis
just created -- the guest was booted from an image we pulled and configured,
and the connection is over a localhost port forward that is not exposed to
the network.

If propolis is used in a scenario where the SSH connection traverses an
untrusted network, host key verification should be implemented by the
caller using a custom SSH client rather than the built-in one.
