// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package egress implements DNS-based egress filtering for VM network traffic.
//
// It intercepts DNS queries at the relay level, blocking resolution of
// non-allowed hostnames with NXDOMAIN responses and snooping responses for
// allowed hostnames to learn their IPs. Resolved IPs become time-limited
// dynamic firewall rules, restricting the VM to connecting only to hosts
// in the configured allowlist.
package egress
