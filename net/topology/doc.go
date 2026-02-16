// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package topology defines shared network topology constants for propolis
// microVMs. These constants describe the virtual network layout used by
// gvisor-tap-vsock: subnet, gateway, guest IP, MAC address, and MTU.
//
// Both the in-process runner networking and the hosted network provider
// import these values to ensure a consistent topology.
package topology
