// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"encoding/binary"
	"fmt"

	"github.com/stacklok/go-microvm/net/firewall"
)

const (
	ethHeaderLen  = 14
	ipv4MinLen    = 20
	udpHeaderLen  = 8
	etherTypeIPv4 = 0x0800
)

// IsDNSQuery checks if a frame is a UDP packet to port 53.
func IsDNSQuery(hdr *firewall.PacketHeader) bool {
	return hdr != nil && hdr.Protocol == 17 && hdr.DstPort == 53
}

// IsDNSResponse checks if a frame is a UDP packet from port 53.
func IsDNSResponse(hdr *firewall.PacketHeader) bool {
	return hdr != nil && hdr.Protocol == 17 && hdr.SrcPort == 53
}

// ExtractUDPPayload returns the UDP payload bytes from a raw Ethernet frame,
// skipping the Ethernet, IPv4 (respecting IHL), and UDP headers.
func ExtractUDPPayload(frame []byte) ([]byte, error) {
	if len(frame) < ethHeaderLen+ipv4MinLen {
		return nil, fmt.Errorf("frame too short for IPv4: %d bytes", len(frame))
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != etherTypeIPv4 {
		return nil, fmt.Errorf("not IPv4: ethertype 0x%04x", etherType)
	}

	ipStart := ethHeaderLen
	ihl := int(frame[ipStart]&0x0F) * 4
	if ihl < ipv4MinLen {
		return nil, fmt.Errorf("invalid IHL: %d", ihl/4)
	}

	udpStart := ipStart + ihl
	if len(frame) < udpStart+udpHeaderLen {
		return nil, fmt.Errorf("frame too short for UDP header: need %d, have %d", udpStart+udpHeaderLen, len(frame))
	}

	payloadStart := udpStart + udpHeaderLen
	return frame[payloadStart:], nil
}

// BuildResponseFrame constructs a complete Ethernet frame for a DNS response
// by swapping headers from the query frame and replacing the UDP payload.
func BuildResponseFrame(queryFrame []byte, dnsResponse []byte) ([]byte, error) {
	if len(queryFrame) < ethHeaderLen+ipv4MinLen+udpHeaderLen {
		return nil, fmt.Errorf("query frame too short: %d bytes", len(queryFrame))
	}

	ipStart := ethHeaderLen
	ihl := int(queryFrame[ipStart]&0x0F) * 4
	if ihl < ipv4MinLen {
		return nil, fmt.Errorf("invalid IHL: %d", ihl/4)
	}

	udpStart := ipStart + ihl
	headerLen := udpStart + udpHeaderLen

	if len(queryFrame) < headerLen {
		return nil, fmt.Errorf("query frame too short for headers: need %d, have %d", headerLen, len(queryFrame))
	}

	// Build the response frame: headers + DNS response payload.
	resp := make([]byte, headerLen+len(dnsResponse))
	copy(resp, queryFrame[:headerLen])

	// 1. Swap Ethernet MAC addresses (dst[0:6] <-> src[6:12]).
	copy(resp[0:6], queryFrame[6:12])
	copy(resp[6:12], queryFrame[0:6])

	// 2. Swap IP addresses (src[ipStart+12:ipStart+16] <-> dst[ipStart+16:ipStart+20]).
	copy(resp[ipStart+12:ipStart+16], queryFrame[ipStart+16:ipStart+20])
	copy(resp[ipStart+16:ipStart+20], queryFrame[ipStart+12:ipStart+16])

	// 3. Swap UDP ports (src[udpStart:udpStart+2] <-> dst[udpStart+2:udpStart+4]).
	copy(resp[udpStart:udpStart+2], queryFrame[udpStart+2:udpStart+4])
	copy(resp[udpStart+2:udpStart+4], queryFrame[udpStart:udpStart+2])

	// 4. Replace UDP payload.
	copy(resp[headerLen:], dnsResponse)

	// 5. Update IP total length.
	ipTotalLen := uint16(ihl + udpHeaderLen + len(dnsResponse))
	binary.BigEndian.PutUint16(resp[ipStart+2:ipStart+4], ipTotalLen)

	// 6. Recompute IP header checksum.
	// Zero out the checksum field first.
	resp[ipStart+10] = 0
	resp[ipStart+11] = 0
	binary.BigEndian.PutUint16(resp[ipStart+10:ipStart+12], ipChecksum(resp[ipStart:ipStart+ihl]))

	// 7. Update UDP length and set checksum to 0 (valid for IPv4).
	udpLen := uint16(udpHeaderLen + len(dnsResponse))
	binary.BigEndian.PutUint16(resp[udpStart+4:udpStart+6], udpLen)
	resp[udpStart+6] = 0 // checksum high byte
	resp[udpStart+7] = 0 // checksum low byte

	return resp, nil
}

// ipChecksum computes the IPv4 header checksum per RFC 791.
func ipChecksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 != 0 {
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}
