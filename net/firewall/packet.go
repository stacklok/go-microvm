// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import "encoding/binary"

const (
	// ethHeaderLen is the size of an Ethernet II header (dst MAC + src MAC + ethertype).
	ethHeaderLen = 14

	// ipv4MinLen is the minimum IPv4 header length without options.
	ipv4MinLen = 20

	// etherTypeIPv4 is the EtherType value for IPv4.
	etherTypeIPv4 uint16 = 0x0800
)

// PacketHeader holds the parsed fields from an Ethernet/IPv4 frame that
// the firewall needs for rule matching and connection tracking.
type PacketHeader struct {
	SrcIP    [4]byte
	DstIP    [4]byte
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
}

// ParseHeaders extracts IP and transport-layer fields from a raw Ethernet
// frame using fixed-offset parsing.
//
// Non-IPv4 frames (ARP, IPv6, etc.) return nil -- callers should treat nil
// as "always pass through" since these protocols are needed for basic
// network bootstrapping (e.g. ARP resolution, DHCP).
func ParseHeaders(frame []byte) *PacketHeader {
	// Need at least an Ethernet header to read the EtherType.
	if len(frame) < ethHeaderLen {
		return nil
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != etherTypeIPv4 {
		return nil
	}

	ipStart := ethHeaderLen

	// Need at least the minimum IPv4 header.
	if len(frame) < ipStart+ipv4MinLen {
		return nil
	}

	// Internet Header Length is the low nibble of the first byte, in 32-bit words.
	ihl := int(frame[ipStart]&0x0F) * 4
	if ihl < ipv4MinLen {
		return nil
	}

	if len(frame) < ipStart+ihl {
		return nil
	}

	hdr := &PacketHeader{
		Protocol: frame[ipStart+9],
	}
	copy(hdr.SrcIP[:], frame[ipStart+12:ipStart+16])
	copy(hdr.DstIP[:], frame[ipStart+16:ipStart+20])

	// Extract ports for TCP (6) and UDP (17). Both place src/dst port
	// in the first 4 bytes of the transport header.
	transportStart := ipStart + ihl
	if (hdr.Protocol == 6 || hdr.Protocol == 17) && len(frame) >= transportStart+4 {
		hdr.SrcPort = binary.BigEndian.Uint16(frame[transportStart : transportStart+2])
		hdr.DstPort = binary.BigEndian.Uint16(frame[transportStart+2 : transportStart+4])
	}

	return hdr
}
