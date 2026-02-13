// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilter_Verdict(t *testing.T) {
	t.Parallel()

	egressHTTP := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{93, 184, 216, 34},
		Protocol: 6,
		SrcPort:  54321,
		DstPort:  80,
	}

	// Return traffic for egressHTTP.
	ingressHTTPReturn := &PacketHeader{
		SrcIP:    [4]byte{93, 184, 216, 34},
		DstIP:    [4]byte{10, 0, 0, 1},
		Protocol: 6,
		SrcPort:  80,
		DstPort:  54321,
	}

	egressDNS := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{8, 8, 8, 8},
		Protocol: 17,
		SrcPort:  40000,
		DstPort:  53,
	}

	egressSSH := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{172, 16, 0, 1},
		Protocol: 6,
		SrcPort:  55555,
		DstPort:  22,
	}

	tests := []struct {
		name          string
		rules         []Rule
		defaultAction Action
		dir           Direction
		hdr           *PacketHeader
		want          Action
		setup         func(f *Filter) // optional pre-test setup
	}{
		{
			name:          "default action when no rules match",
			rules:         nil,
			defaultAction: Deny,
			dir:           Egress,
			hdr:           egressHTTP,
			want:          Deny,
		},
		{
			name: "allow rule matches",
			rules: []Rule{
				{Direction: Egress, Action: Allow, Protocol: 6, DstPort: 80},
			},
			defaultAction: Deny,
			dir:           Egress,
			hdr:           egressHTTP,
			want:          Allow,
		},
		{
			name: "deny rule matches",
			rules: []Rule{
				{Direction: Egress, Action: Deny, Protocol: 6, DstPort: 22},
			},
			defaultAction: Allow,
			dir:           Egress,
			hdr:           egressSSH,
			want:          Deny,
		},
		{
			name: "first-match-wins: first rule takes effect",
			rules: []Rule{
				{Direction: Egress, Action: Deny, Protocol: 6, DstPort: 80},
				{Direction: Egress, Action: Allow, Protocol: 6, DstPort: 80},
			},
			defaultAction: Allow,
			dir:           Egress,
			hdr:           egressHTTP,
			want:          Deny,
		},
		{
			name: "conntrack fast path: established connection returns Allow",
			rules: []Rule{
				{Direction: Egress, Action: Allow, Protocol: 6, DstPort: 80},
			},
			defaultAction: Deny,
			dir:           Ingress,
			hdr:           ingressHTTPReturn,
			want:          Allow,
			setup: func(f *Filter) {
				// Simulate an earlier allowed egress that was tracked.
				_ = f.Verdict(Egress, egressHTTP)
			},
		},
		{
			name: "allow rule tracks the connection",
			rules: []Rule{
				{Direction: Egress, Action: Allow, Protocol: 17, DstPort: 53},
			},
			defaultAction: Deny,
			dir:           Egress,
			hdr:           egressDNS,
			want:          Allow,
		},
		{
			name: "deny rule does not track",
			rules: []Rule{
				{Direction: Egress, Action: Deny, Protocol: 6, DstPort: 22},
			},
			defaultAction: Deny,
			dir:           Egress,
			hdr:           egressSSH,
			want:          Deny,
		},
		{
			name: "CIDR-based rule match",
			rules: []Rule{
				{
					Direction: Egress,
					Action:    Allow,
					Protocol:  6,
					DstCIDR: func() net.IPNet {
						_, n, _ := net.ParseCIDR("93.184.216.0/24")
						return *n
					}(),
				},
			},
			defaultAction: Deny,
			dir:           Egress,
			hdr:           egressHTTP,
			want:          Allow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := NewFilter(tt.rules, tt.defaultAction)
			if tt.setup != nil {
				tt.setup(f)
			}

			got := f.Verdict(tt.dir, tt.hdr)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestFilter_DenyDoesNotTrack(t *testing.T) {
	t.Parallel()

	f := NewFilter([]Rule{
		{Direction: Egress, Action: Deny, Protocol: 6, DstPort: 22},
	}, Deny)

	hdrOut := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{172, 16, 0, 1},
		Protocol: 6,
		SrcPort:  55555,
		DstPort:  22,
	}

	// Deny the packet.
	got := f.Verdict(Egress, hdrOut)
	assert.Equal(t, Deny, got)

	// Return traffic should NOT be established since deny doesn't track.
	hdrReturn := &PacketHeader{
		SrcIP:    [4]byte{172, 16, 0, 1},
		DstIP:    [4]byte{10, 0, 0, 1},
		Protocol: 6,
		SrcPort:  22,
		DstPort:  55555,
	}
	got = f.Verdict(Ingress, hdrReturn)
	assert.Equal(t, Deny, got)
}
