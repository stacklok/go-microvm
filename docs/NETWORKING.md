# Networking and Firewall

This document provides a deep dive into the propolis networking subsystem,
including the in-process userspace network stack, wire protocol, firewall
architecture, and extension points.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [QEMU Wire Protocol](#qemu-wire-protocol)
- [Network Topology](#network-topology)
- [VirtualNetwork Lifecycle](#virtualnetwork-lifecycle)
- [Firewall Architecture](#firewall-architecture)
- [Performance](#performance)
- [Usage Examples](#usage-examples)
- [Provider Interface](#provider-interface)

## Overview

propolis runs an in-process userspace network stack powered by
[gvisor-tap-vsock](https://github.com/containers/gvisor-tap-vsock). All VM
traffic flows through a single Unix domain socket as Ethernet frames. There is
no kernel networking between host and guest, and no separate gvproxy binary is
needed.

The gvisor-tap-vsock library (used by podman machine, lima, and libkrun) is
imported directly as a Go dependency. It provides a complete virtual network
stack including DHCP, DNS, and TCP port forwarding -- all running inside the
same process as the propolis library.

Key properties:

- **Single process**: The network stack runs in-process as goroutines. No
  external binaries to manage, no PID tracking, no signal handling.
- **Userspace only**: All packet processing happens in Go. No iptables, no
  eBPF, no network namespaces.
- **Frame-level access**: Every Ethernet frame passes through Go code,
  enabling the optional firewall to inspect and filter traffic.

## Architecture

There are two paths through the networking subsystem depending on whether the
firewall is enabled.

### Without Firewall

When no firewall rules are configured, the VM socket connects directly to the
VirtualNetwork via `AcceptQemu()`:

```
+----------+                    +-------------------+          +---------+
| Guest VM |                    | VirtualNetwork    |          |  Host   |
|          |   Unix socket      | (gVisor netstack) |  Go net  | Network |
| virtio-  |===(QEMU wire)===>  |                   |--------->|         |
| net      |   SOCK_STREAM      | DHCP, DNS,        |          |         |
|          |   4B BE + frame    | port forwarding   |          |         |
+----------+                    +-------------------+          +---------+
```

### With Firewall

When firewall rules are configured via `WithFirewallRules()`, a relay is
inserted between the VM socket and the VirtualNetwork. The relay intercepts
every Ethernet frame, parses headers, and applies allow/deny rules with
stateful connection tracking:

```
+----------+                  +-----------------+               +-------------------+
| Guest VM |                  | Relay + Filter  |               | VirtualNetwork    |
|          |   Unix socket    |                 |   net.Pipe    | (gVisor netstack) |
| virtio-  |===(QEMU wire)===>| egress gor. --->|===(in-mem)===>|                   |
| net      |   SOCK_STREAM    | ingress gor.<---|<==(in-mem)====|   DHCP, DNS,      |
|          |   4B BE + frame  |                 |               |   port forwarding |
+----------+                  | - parse ETH/IP  |               +-------------------+
                              | - conntrack     |                        |
                              | - rule matching |                   +---------+
                              | - metrics       |                   |  Host   |
                              +-----------------+                   | Network |
                                                                    +---------+
```

The relay creates a `net.Pipe()` -- one end is passed to
`VirtualNetwork.AcceptQemu()`, the other is used by the relay. Two goroutines
handle egress (VM to network) and ingress (network to VM) independently.

## QEMU Wire Protocol

The QEMU transport is a stream protocol over a Unix domain socket
(`SOCK_STREAM`). Every Ethernet frame is prefixed with a 4-byte big-endian
length header.

### Frame Format

```
+---+---+---+---+---+---+---+---+---+---+---+...
| Length (4B BE) |         Ethernet Frame          |
+---+---+---+---+---+---+---+---+---+---+---+...
|<--- 4 bytes -->|<-------- N bytes ------------->|
```

- **Length field**: `uint32`, big-endian. Value is the number of bytes in the
  Ethernet frame that follows (does NOT include the 4-byte header itself).
- **Ethernet frame**: Raw L2 frame starting with destination MAC address.
- **No handshake**: Data flows immediately after socket connection.
- **Max frame size**: Practically limited by MTU (default 1500 bytes).

### Why QEMU Mode

libkrun's `krun_add_net_unixstream` speaks the QEMU wire protocol: a
`SOCK_STREAM` Unix socket with 4-byte big-endian length-prefixed Ethernet
frames. The gvisor-tap-vsock library's `AcceptQemu()` method uses the same
framing, making them directly compatible.

### Protocol Comparison

| Protocol | Header | Byte Order | Socket Type | Use Case |
|----------|--------|------------|-------------|----------|
| **QEMU** | 4 bytes | Big-endian | SOCK_STREAM | libkrun, QEMU |
| VfKit | None | N/A | SOCK_DGRAM | macOS Virt.framework |
| BESS | None | N/A | SOCK_SEQPACKET | User Mode Linux |

## Network Topology

```
+---------------------------------------------------+
|                   Host Machine                     |
|                                                    |
|  +---------------+    Unix socket   +-----------+  |
|  | VirtualNetwork|---(SOCK_STREAM)->|  libkrun  |  |
|  | (in-process)  |  4-byte BE len  |  virtio-  |  |
|  |               |  prefix frames  |  net      |  |
|  | Gateway:      |                 |           |  |
|  | 192.168.127.1 |                 +-----------+  |
|  |               |                      |         |
|  | DHCP server   |                 +----v-----+   |
|  | DNS server    |                 | Guest VM |   |
|  | Port forwards |                 |          |   |
|  +---------------+                 | eth0:    |   |
|        |                           | 192.168. |   |
|        |  Port forwards:           | 127.2    |   |
|        |  localhost:8080           |          |   |
|        +-----> guest:80            +----------+   |
|        |  localhost:2222                          |
|        +-----> guest:22                           |
+---------------------------------------------------+
```

| Property | Value |
|----------|-------|
| Gateway | 192.168.127.1 (VirtualNetwork, in-process) |
| Guest IP | 192.168.127.2 (DHCP assigned) |
| Subnet | 192.168.127.0/24 |
| Socket type | Unix domain, SOCK_STREAM |
| Wire format | 4-byte big-endian length prefix + Ethernet frame |
| DHCP | Built into VirtualNetwork |
| DNS | Built into VirtualNetwork |
| Port forwarding | TCP, host-to-guest only |

## VirtualNetwork Lifecycle

### Start

`Provider.Start()` performs the following:

1. Creates a `virtualnetwork.New()` instance with the network configuration
   (subnet, gateway, port forwards, DHCP, DNS).
2. Creates a Unix listener at the socket path (inside the data directory).
3. Starts a goroutine to accept the VM connection on the Unix socket.
4. If firewall rules are configured, creates a `net.Pipe()` and starts the
   relay between the VM connection and the pipe. The VirtualNetwork side
   calls `AcceptQemu()` on the pipe end. If no firewall is configured, the
   VM connection is passed directly to `AcceptQemu()`.
5. Returns once the listener is ready.

### Stop

`Provider.Stop()` tears down everything:

1. Cancels the context, which signals all goroutines to exit.
2. The `AcceptQemu()` goroutine returns when the context is cancelled.
3. The relay goroutines (if running) exit when the context is cancelled
   or the connections are closed.
4. Closes the Unix listener and removes the socket file.

All goroutines are managed via `errgroup` and context cancellation. There
are no external processes to signal or reap.

## Firewall Architecture

The firewall provides frame-level packet filtering with stateful connection
tracking. It operates entirely in userspace by intercepting Ethernet frames
as they pass between the VM socket and the VirtualNetwork.

### Frame-Level Interception

The firewall inserts a relay between the VM's Unix socket and the
VirtualNetwork. The relay reads each frame, parses the Ethernet and IP
headers, applies firewall rules, and either forwards or drops the frame.

### Packet Parsing

Each Ethernet frame is parsed at fixed offsets with zero allocations:

1. **Ethernet header** (14 bytes): Destination MAC (6B), Source MAC (6B),
   EtherType (2B). EtherType 0x0800 = IPv4, 0x0806 = ARP, 0x86DD = IPv6.

2. **IPv4 header** (20+ bytes, starts at offset 14): Protocol field at
   byte 23 (6=TCP, 17=UDP, 1=ICMP). Source IP at bytes 26-29, destination
   IP at bytes 30-33. IHL field gives header length.

3. **TCP/UDP header** (starts at offset 14 + IHL*4): Source port (2B),
   destination port (2B).

Non-IPv4 frames (ARP, IPv6, LLDP) are always passed through without
filtering. They are essential for the network stack to function (ARP
resolution, etc.).

### Rule Model

Each firewall rule specifies:

| Field | Type | Description |
|-------|------|-------------|
| Direction | Ingress/Egress | Ingress = outside to VM, Egress = VM to outside |
| Action | Allow/Deny | What to do when matched |
| Protocol | uint8 | 6=TCP, 17=UDP, 1=ICMP; 0=any |
| SrcCIDR | net.IPNet | Source IP range |
| DstCIDR | net.IPNet | Destination IP range |
| SrcPort | uint16 | Source port; 0=any |
| DstPort | uint16 | Destination port; 0=any |

Rules are evaluated in order. **First match wins** (same as iptables). If no
rule matches, the default action applies (configurable via
`WithFirewallDefaultAction()`; defaults to Allow when no rules are set).

### Stateful Connection Tracking

The firewall tracks active connections using a 5-tuple key:

```
connKey = { protocol, srcIP, dstIP, srcPort, dstPort }
```

When a rule allows a packet, the connection tracker records the flow. Return
traffic (with source and destination swapped) is automatically allowed via a
reverse-lookup in the connection table. This means you do not need explicit
ingress rules for return traffic from allowed egress connections.

**TTLs**:
- TCP connections: 5 minutes idle timeout
- UDP flows: 30 seconds idle timeout

An expiry goroutine periodically sweeps the connection table to remove stale
entries.

**Memory**: Each conntrack entry is approximately 100 bytes. A typical VM
workload of 200-500 concurrent flows uses around 50 KB.

### Filter Verdict Flow

For each frame, the filter follows this path:

1. **Conntrack fast path**: Check if the packet belongs to an already-allowed
   flow via reverse-lookup. If yes, allow immediately (most common case for
   established connections).
2. **Rule walk**: Iterate through rules in order. First match wins. If the
   matching rule allows the packet, record it in the connection tracker.
3. **Default action**: If no rule matches, apply the configured default
   action (Allow or Deny).

### Relay Hot Path

The relay runs two goroutines:

- **Egress goroutine**: Reads frames from the VM socket, applies filter,
  writes to the VirtualNetwork pipe.
- **Ingress goroutine**: Reads frames from the VirtualNetwork pipe, applies
  filter, writes to the VM socket.

Each goroutine uses a buffered reader (64 KB) and a reusable frame buffer.
Frames that the filter denies are silently dropped (not forwarded). Atomic
counters track forwarded frames, dropped frames, and bytes forwarded.

## Performance

The firewall adds minimal overhead per Ethernet frame:

| Operation | Cost |
|-----------|------|
| Read frame (4-byte prefix + payload) | Required regardless -- no added cost |
| Parse Ethernet + IPv4 headers | ~10ns -- fixed-offset reads, no allocations |
| Connection tracker lookup | ~20ns -- map lookup under RLock |
| Rule matching (per rule, on miss) | ~5ns -- simple comparisons |
| Write frame (forward) | Required regardless -- no added cost |

**Total added latency**: ~50-100ns per frame. At 1 Gbps with 1500-byte frames
(~83,000 frames/sec), the firewall adds roughly 4ms of CPU time per second.
This is negligible at typical VM throughput.

**Memory overhead**:
- Connection tracker: ~100 bytes per entry, typically 200-500 entries = ~50 KB
- Frame buffer: ~2 KB per direction, reused
- Rule slice: typically <20 rules = negligible

## Usage Examples

### Default-Deny with DNS and HTTPS Egress

Allow the VM to make DNS queries and HTTPS connections, but deny all other
outbound traffic. Inbound traffic is denied except on explicitly allowed ports.
Return traffic for allowed connections is automatically permitted via
connection tracking.

```go
import "github.com/stacklok/propolis/net/firewall"

vm, err := propolis.Run(ctx, "my-app:latest",
    propolis.WithPorts(
        propolis.PortForward{Host: 8080, Guest: 80},
        propolis.PortForward{Host: 2222, Guest: 22},
    ),
    propolis.WithFirewallDefaultAction(firewall.Deny),
    propolis.WithFirewallRules(
        // Egress: allow DNS and HTTPS
        firewall.Rule{
            Direction: firewall.Egress,
            Action:    firewall.Allow,
            Protocol:  17, // UDP
            DstPort:   53, // DNS
        },
        firewall.Rule{
            Direction: firewall.Egress,
            Action:    firewall.Allow,
            Protocol:  6, // TCP
            DstPort:   443, // HTTPS
        },
        // Ingress: allow SSH and HTTP
        firewall.Rule{
            Direction: firewall.Ingress,
            Action:    firewall.Allow,
            Protocol:  6,
            DstPort:   22,
        },
        firewall.Rule{
            Direction: firewall.Ingress,
            Action:    firewall.Allow,
            Protocol:  6,
            DstPort:   80,
        },
    ),
)
```

### Allow Specific Ingress Ports Only

```go
vm, err := propolis.Run(ctx, "my-server:latest",
    propolis.WithPorts(
        propolis.PortForward{Host: 8443, Guest: 443},
        propolis.PortForward{Host: 6443, Guest: 6443},
    ),
    propolis.WithFirewallDefaultAction(firewall.Deny),
    propolis.WithFirewallRules(
        // Allow all egress (VM can reach the internet)
        firewall.Rule{
            Direction: firewall.Egress,
            Action:    firewall.Allow,
        },
        // Allow specific ingress ports
        firewall.Rule{
            Direction: firewall.Ingress,
            Action:    firewall.Allow,
            Protocol:  6,
            DstPort:   443,
        },
        firewall.Rule{
            Direction: firewall.Ingress,
            Action:    firewall.Allow,
            Protocol:  6,
            DstPort:   6443,
        },
        firewall.Rule{
            Direction: firewall.Ingress,
            Action:    firewall.Allow,
            Protocol:  6,
            DstPort:   22,
        },
    ),
)
```

### No Firewall (Default)

When no firewall rules are configured, all traffic passes through
unrestricted. This is the default behavior:

```go
vm, err := propolis.Run(ctx, "alpine:latest",
    propolis.WithPorts(propolis.PortForward{Host: 8080, Guest: 80}),
)
```

## Provider Interface

The networking layer is abstracted behind the `net.Provider` interface:

```go
type Provider interface {
    // Start launches the network provider. Must block until ready.
    Start(ctx context.Context, cfg Config) error

    // SocketPath returns the Unix socket path for virtio-net.
    SocketPath() string

    // Stop terminates the provider and cleans up.
    Stop()
}
```

`Config` contains:
- `LogDir` -- directory for log files
- `Forwards` -- slice of `PortForward{Host, Guest}` for TCP forwarding

The default provider creates a VirtualNetwork in-process. There is no
external binary to manage, no PID to track, and no process signals to handle.

### Implementing a Custom Provider

To replace the default in-process networking with an alternative backend
(e.g., passt, slirp4netns, or a custom bridge):

1. Implement the `net.Provider` interface.
2. `Start()` must block until the Unix socket is ready for connections.
3. The socket must use `SOCK_STREAM` with 4-byte big-endian length-prefixed
   Ethernet frames (the QEMU transport protocol).
4. Pass your provider via `propolis.WithNetProvider(myProvider)`.

The `SocketPath()` return value is passed to the runner as the Unix socket
path for `krun_add_net_unixstream`. See `net/provider_impl.go` for the
reference implementation.
