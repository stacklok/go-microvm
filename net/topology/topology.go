// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package topology

// Network topology constants for the go-microvm virtual network.
// These match the gvisor-tap-vsock defaults used by libkrun/krunvm.
const (
	// Subnet is the CIDR notation for the virtual network subnet.
	Subnet = "192.168.127.0/24"

	// GatewayIP is the IP address of the virtual network gateway
	// (the host side). Services exposed to the guest listen here.
	GatewayIP = "192.168.127.1"

	// GatewayMAC is the MAC address of the virtual network gateway.
	GatewayMAC = "5a:94:ef:e4:0c:ee"

	// GuestIP is the IP address assigned to the guest VM.
	GuestIP = "192.168.127.2"

	// MTU is the maximum transmission unit for the virtual network.
	MTU = 1500
)
