// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/net/firewall"
)

// buildTestUDPFrame constructs a minimal Ethernet + IPv4 + UDP frame with
// the given parameters and payload.
func buildTestUDPFrame(srcMAC, dstMAC [6]byte, srcIP, dstIP [4]byte, srcPort, dstPort uint16, payload []byte) []byte {
	ihl := 5
	ipHdrLen := ihl * 4
	udpLen := udpHeaderLen + len(payload)
	totalLen := ethHeaderLen + ipHdrLen + udpLen

	frame := make([]byte, totalLen)

	// Ethernet header.
	copy(frame[0:6], dstMAC[:])
	copy(frame[6:12], srcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)

	// IPv4 header.
	ipStart := ethHeaderLen
	frame[ipStart] = byte(0x40 | ihl) // version 4, IHL 5
	binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], uint16(ipHdrLen+udpLen))
	frame[ipStart+8] = 64 // TTL
	frame[ipStart+9] = 17 // UDP
	copy(frame[ipStart+12:ipStart+16], srcIP[:])
	copy(frame[ipStart+16:ipStart+20], dstIP[:])

	// IP checksum.
	frame[ipStart+10] = 0
	frame[ipStart+11] = 0
	binary.BigEndian.PutUint16(frame[ipStart+10:ipStart+12], ipChecksum(frame[ipStart:ipStart+ipHdrLen]))

	// UDP header.
	udpStart := ipStart + ipHdrLen
	binary.BigEndian.PutUint16(frame[udpStart:udpStart+2], srcPort)
	binary.BigEndian.PutUint16(frame[udpStart+2:udpStart+4], dstPort)
	binary.BigEndian.PutUint16(frame[udpStart+4:udpStart+6], uint16(udpLen))
	// Checksum = 0 (valid for IPv4).

	// Payload.
	copy(frame[udpStart+udpHeaderLen:], payload)

	return frame
}

func TestIsDNSQuery(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hdr  *firewall.PacketHeader
		want bool
	}{
		{"UDP to port 53", &firewall.PacketHeader{Protocol: 17, DstPort: 53}, true},
		{"UDP from port 53", &firewall.PacketHeader{Protocol: 17, SrcPort: 53, DstPort: 1234}, false},
		{"TCP to port 53", &firewall.PacketHeader{Protocol: 6, DstPort: 53}, false},
		{"nil header", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsDNSQuery(tt.hdr))
		})
	}
}

func TestIsDNSResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hdr  *firewall.PacketHeader
		want bool
	}{
		{"UDP from port 53", &firewall.PacketHeader{Protocol: 17, SrcPort: 53}, true},
		{"UDP to port 53", &firewall.PacketHeader{Protocol: 17, DstPort: 53, SrcPort: 1234}, false},
		{"TCP from port 53", &firewall.PacketHeader{Protocol: 6, SrcPort: 53}, false},
		{"nil header", nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsDNSResponse(tt.hdr))
		})
	}
}

func TestExtractUDPPayload(t *testing.T) {
	t.Parallel()

	payload := []byte("test dns payload")
	frame := buildTestUDPFrame(
		[6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		[6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		[4]byte{192, 168, 127, 2},
		[4]byte{192, 168, 127, 1},
		12345, 53,
		payload,
	)

	got, err := ExtractUDPPayload(frame)
	require.NoError(t, err)
	assert.Equal(t, payload, got)
}

func TestExtractUDPPayload_TooShort(t *testing.T) {
	t.Parallel()

	_, err := ExtractUDPPayload(make([]byte, 10))
	assert.Error(t, err)
}

func TestBuildResponseFrame(t *testing.T) {
	t.Parallel()

	srcMAC := [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dstMAC := [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	srcIP := [4]byte{192, 168, 127, 2}
	dstIP := [4]byte{192, 168, 127, 1}

	queryPayload := []byte("query")
	queryFrame := buildTestUDPFrame(srcMAC, dstMAC, srcIP, dstIP, 12345, 53, queryPayload)

	responsePayload := []byte("nxdomain-response")
	resp, err := BuildResponseFrame(queryFrame, responsePayload)
	require.NoError(t, err)

	// Check MACs are swapped.
	assert.Equal(t, srcMAC[:], resp[0:6], "dst MAC should be original src MAC")
	assert.Equal(t, dstMAC[:], resp[6:12], "src MAC should be original dst MAC")

	// Check IPs are swapped.
	ipStart := ethHeaderLen
	var respSrcIP, respDstIP [4]byte
	copy(respSrcIP[:], resp[ipStart+12:ipStart+16])
	copy(respDstIP[:], resp[ipStart+16:ipStart+20])
	assert.Equal(t, dstIP, respSrcIP, "response src IP should be query dst IP")
	assert.Equal(t, srcIP, respDstIP, "response dst IP should be query src IP")

	// Check ports are swapped.
	ihl := int(resp[ipStart]&0x0F) * 4
	udpStart := ipStart + ihl
	respSrcPort := binary.BigEndian.Uint16(resp[udpStart : udpStart+2])
	respDstPort := binary.BigEndian.Uint16(resp[udpStart+2 : udpStart+4])
	assert.Equal(t, uint16(53), respSrcPort)
	assert.Equal(t, uint16(12345), respDstPort)

	// Check UDP length.
	udpLen := binary.BigEndian.Uint16(resp[udpStart+4 : udpStart+6])
	assert.Equal(t, uint16(udpHeaderLen+len(responsePayload)), udpLen)

	// Check UDP checksum is zero.
	udpCksum := binary.BigEndian.Uint16(resp[udpStart+6 : udpStart+8])
	assert.Equal(t, uint16(0), udpCksum)

	// Check payload.
	got, err := ExtractUDPPayload(resp)
	require.NoError(t, err)
	assert.Equal(t, responsePayload, got)

	// Verify IP checksum is correct.
	verifySum := ipChecksum(resp[ipStart : ipStart+ihl])
	assert.Equal(t, uint16(0), verifySum, "IP checksum should verify to 0")
}

func TestBuildResponseFrame_TooShort(t *testing.T) {
	t.Parallel()

	_, err := BuildResponseFrame(make([]byte, 10), []byte("resp"))
	assert.Error(t, err)
}
