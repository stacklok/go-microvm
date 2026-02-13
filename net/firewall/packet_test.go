// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildEthIPv4Frame constructs a minimal Ethernet + IPv4 + transport header frame.
// ihl is the IP header length in 32-bit words (minimum 5). Extra IHL bytes
// are zero-filled options.
func buildEthIPv4Frame(srcIP, dstIP [4]byte, proto uint8, srcPort, dstPort uint16, ihl int) []byte {
	if ihl < 5 {
		ihl = 5
	}
	ipHdrLen := ihl * 4
	// 14 (eth) + ipHdrLen + 4 (ports)
	frame := make([]byte, ethHeaderLen+ipHdrLen+4)

	// Ethernet header: dst MAC (6), src MAC (6), EtherType (2)
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)

	// IPv4 header
	ipStart := ethHeaderLen
	frame[ipStart] = byte(0x40 | (ihl & 0x0F)) // version 4, IHL
	totalLen := ipHdrLen + 4                   // IP header + 4 bytes transport
	binary.BigEndian.PutUint16(frame[ipStart+2:ipStart+4], uint16(totalLen))
	frame[ipStart+9] = proto
	copy(frame[ipStart+12:ipStart+16], srcIP[:])
	copy(frame[ipStart+16:ipStart+20], dstIP[:])

	// Transport header (first 4 bytes: src port, dst port)
	tStart := ipStart + ipHdrLen
	binary.BigEndian.PutUint16(frame[tStart:tStart+2], srcPort)
	binary.BigEndian.PutUint16(frame[tStart+2:tStart+4], dstPort)

	return frame
}

func TestParseHeaders(t *testing.T) {
	t.Parallel()

	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{192, 168, 1, 100}

	tests := []struct {
		name    string
		frame   []byte
		wantNil bool
		want    *PacketHeader
	}{
		{
			name:    "IPv4 TCP frame",
			frame:   buildEthIPv4Frame(srcIP, dstIP, 6, 12345, 80, 5),
			wantNil: false,
			want: &PacketHeader{
				SrcIP:    srcIP,
				DstIP:    dstIP,
				Protocol: 6,
				SrcPort:  12345,
				DstPort:  80,
			},
		},
		{
			name:    "IPv4 UDP frame",
			frame:   buildEthIPv4Frame(srcIP, dstIP, 17, 5353, 53, 5),
			wantNil: false,
			want: &PacketHeader{
				SrcIP:    srcIP,
				DstIP:    dstIP,
				Protocol: 17,
				SrcPort:  5353,
				DstPort:  53,
			},
		},
		{
			name: "ARP frame returns nil",
			frame: func() []byte {
				f := make([]byte, 42) // typical ARP
				binary.BigEndian.PutUint16(f[12:14], 0x0806)
				return f
			}(),
			wantNil: true,
		},
		{
			name:    "too-short frame returns nil",
			frame:   make([]byte, 10),
			wantNil: true,
		},
		{
			name: "IPv6 frame returns nil",
			frame: func() []byte {
				f := make([]byte, 60)
				binary.BigEndian.PutUint16(f[12:14], 0x86DD)
				return f
			}(),
			wantNil: true,
		},
		{
			name:    "IPv4 frame with IP options (IHL 6)",
			frame:   buildEthIPv4Frame(srcIP, dstIP, 6, 4000, 443, 6),
			wantNil: false,
			want: &PacketHeader{
				SrcIP:    srcIP,
				DstIP:    dstIP,
				Protocol: 6,
				SrcPort:  4000,
				DstPort:  443,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ParseHeaders(tt.frame)
			if tt.wantNil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, tt.want.SrcIP, got.SrcIP)
			assert.Equal(t, tt.want.DstIP, got.DstIP)
			assert.Equal(t, tt.want.Protocol, got.Protocol)
			assert.Equal(t, tt.want.SrcPort, got.SrcPort)
			assert.Equal(t, tt.want.DstPort, got.DstPort)
		})
	}
}
