// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package net defines the networking abstraction for go-microvm microVMs.
//
// A [Provider] manages the lifecycle of a network backend that connects the
// host to the guest VM. The default implementation uses an in-process
// gvisor-tap-vsock VirtualNetwork with optional frame-level firewall, but
// callers may supply any implementation that satisfies the [Provider] interface.
//
// Port forwarding from host to guest is configured via [PortForward] entries
// in the [Config] passed to [Provider.Start].
package net
