// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package net

import (
	"context"

	"github.com/stacklok/propolis/net/firewall"
)

// PortForward describes a TCP port forwarding rule from host to guest.
type PortForward struct {
	Host  uint16
	Guest uint16
}

// EgressPolicy restricts outbound VM traffic to specific DNS hostnames.
type EgressPolicy struct {
	AllowedHosts []EgressHost
}

// EgressHost defines a single hostname allowed for egress traffic.
type EgressHost struct {
	Name     string   // "api.github.com" or "*.docker.io"
	Ports    []uint16 // empty = all ports
	Protocol uint8    // 0 = both TCP+UDP, 6 = TCP only, 17 = UDP only
}

// Config holds networking configuration for a VM.
type Config struct {
	// LogDir is the directory where the network provider should write logs.
	LogDir string

	// Forwards defines TCP port forwards from the host to the guest VM.
	Forwards []PortForward

	// FirewallRules defines optional packet filtering rules applied to
	// VM traffic. When non-empty, a relay with frame-level filtering is
	// inserted between the VM socket and the virtual network.
	FirewallRules []firewall.Rule

	// FirewallDefaultAction is the action taken when no firewall rule
	// matches a packet. Only used when FirewallRules is non-empty.
	// Defaults to Allow (zero value).
	FirewallDefaultAction firewall.Action

	// EgressPolicy restricts outbound VM traffic to the specified
	// hostnames via DNS-level interception. When non-nil, DNS queries
	// for non-allowed hosts receive NXDOMAIN responses and dynamic
	// firewall rules are created from allowed DNS responses.
	EgressPolicy *EgressPolicy
}

// Provider abstracts the networking backend for a libkrun VM.
// Implementations manage the lifecycle of a userspace network stack
// that provides connectivity between host and guest.
type Provider interface {
	// Start launches the network provider with the given configuration.
	// It must block until the provider is ready to accept connections.
	Start(ctx context.Context, cfg Config) error

	// SocketPath returns the path to the Unix domain socket that the
	// VM runner should use to connect to this network provider.
	SocketPath() string

	// Stop terminates the network provider and cleans up resources.
	Stop()
}
