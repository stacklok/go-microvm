// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import "net"

// Direction indicates whether traffic is flowing into or out of the VM.
type Direction uint8

const (
	// Ingress is traffic from the outside world into the VM.
	Ingress Direction = iota
	// Egress is traffic from the VM to the outside world.
	Egress
)

// Action is the verdict applied to a packet.
type Action uint8

const (
	// Allow permits the packet to be forwarded.
	Allow Action = iota
	// Deny silently drops the packet.
	Deny
)

// Rule describes a single firewall match criterion and its action.
//
// Zero-value fields act as wildcards:
//   - Protocol 0 matches any protocol
//   - A zero-value net.IPNet (nil or empty Mask) matches any IP
//   - Port 0 matches any port
type Rule struct {
	Direction Direction
	Action    Action
	Protocol  uint8 // 6=TCP, 17=UDP; 0 = any
	SrcCIDR   net.IPNet
	DstCIDR   net.IPNet
	SrcPort   uint16 // 0 = any
	DstPort   uint16 // 0 = any
	Comment   string
}

// Matches reports whether the rule matches the given direction and packet header.
func (r *Rule) Matches(dir Direction, hdr *PacketHeader) bool {
	if r.Direction != dir {
		return false
	}

	if r.Protocol != 0 && r.Protocol != hdr.Protocol {
		return false
	}

	if !cidrMatchesIP(r.SrcCIDR, hdr.SrcIP) {
		return false
	}

	if !cidrMatchesIP(r.DstCIDR, hdr.DstIP) {
		return false
	}

	if r.SrcPort != 0 && r.SrcPort != hdr.SrcPort {
		return false
	}

	if r.DstPort != 0 && r.DstPort != hdr.DstPort {
		return false
	}

	return true
}

// cidrMatchesIP checks whether ip falls within cidr. A zero-value IPNet
// (where Mask is nil or has length 0) is treated as a wildcard that matches
// any address.
func cidrMatchesIP(cidr net.IPNet, ip [4]byte) bool {
	if len(cidr.Mask) == 0 {
		return true
	}
	return cidr.Contains(net.IP(ip[:]))
}
