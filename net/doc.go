// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package net defines the networking abstraction for propolis microVMs.
//
// A [Provider] manages the lifecycle of a network backend that connects the
// host to the guest VM. The default implementation uses gvproxy, but callers
// may supply any implementation that satisfies the [Provider] interface.
//
// Port forwarding from host to guest is configured via [PortForward] entries
// in the [Config] passed to [Provider.Start].
package net
