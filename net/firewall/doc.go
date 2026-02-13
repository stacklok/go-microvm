// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package firewall provides frame-level packet filtering for VM network traffic.
//
// It sits between the host network provider (e.g. gvproxy) and the guest VM,
// inspecting Ethernet frames carried over the length-prefixed Unix socket
// protocol used by libkrun. Non-IPv4 traffic (ARP, IPv6) is always passed
// through to ensure basic network bootstrapping works. IPv4 TCP and UDP
// packets are matched against an ordered rule list with first-match-wins
// semantics, and a stateful connection tracker allows return traffic for
// established flows.
package firewall
