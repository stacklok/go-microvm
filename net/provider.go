// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package net

import "context"

// PortForward describes a TCP port forwarding rule from host to guest.
type PortForward struct {
	Host  uint16
	Guest uint16
}

// Config holds networking configuration for a VM.
type Config struct {
	// LogDir is the directory where the network provider should write logs.
	LogDir string

	// Forwards defines TCP port forwards from the host to the guest VM.
	Forwards []PortForward
}

// Provider abstracts the networking backend for a libkrun VM.
// Implementations manage the lifecycle of a userspace network stack
// (e.g. gvproxy) that provides connectivity between host and guest.
type Provider interface {
	// Start launches the network provider with the given configuration.
	// It must block until the provider is ready to accept connections.
	Start(ctx context.Context, cfg Config) error

	// SocketPath returns the path to the Unix domain socket that the
	// VM runner should use to connect to this network provider.
	SocketPath() string

	// PID returns the process ID of the network provider, or 0 if it
	// is not running.
	PID() int

	// BinaryPath returns the path to the network provider binary
	// (e.g. "/usr/bin/gvproxy" or just "gvproxy" if found via PATH).
	// This is persisted in state for crash recovery to verify that a
	// PID still belongs to the expected process.
	BinaryPath() string

	// Stop terminates the network provider process.
	Stop()
}
