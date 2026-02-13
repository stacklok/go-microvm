// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRule_Matches(t *testing.T) {
	t.Parallel()

	_, subnet, _ := net.ParseCIDR("10.0.0.0/8")

	hdr := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{192, 168, 1, 100},
		Protocol: 6,
		SrcPort:  12345,
		DstPort:  80,
	}

	tests := []struct {
		name  string
		rule  Rule
		dir   Direction
		hdr   *PacketHeader
		match bool
	}{
		{
			name: "direction mismatch returns false",
			rule: Rule{
				Direction: Ingress,
				Action:    Allow,
			},
			dir:   Egress,
			hdr:   hdr,
			match: false,
		},
		{
			name: "protocol match specific",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				Protocol:  6,
			},
			dir:   Egress,
			hdr:   hdr,
			match: true,
		},
		{
			name: "protocol mismatch",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				Protocol:  17,
			},
			dir:   Egress,
			hdr:   hdr,
			match: false,
		},
		{
			name: "protocol wildcard 0 matches any",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				Protocol:  0,
			},
			dir:   Egress,
			hdr:   hdr,
			match: true,
		},
		{
			name: "CIDR match specific subnet",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				SrcCIDR:   *subnet,
			},
			dir:   Egress,
			hdr:   hdr,
			match: true,
		},
		{
			name: "CIDR mismatch",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				SrcCIDR: func() net.IPNet {
					_, n, _ := net.ParseCIDR("172.16.0.0/12")
					return *n
				}(),
			},
			dir:   Egress,
			hdr:   hdr,
			match: false,
		},
		{
			name: "CIDR zero-value wildcard matches any",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				SrcCIDR:   net.IPNet{}, // zero-value = wildcard
			},
			dir:   Egress,
			hdr:   hdr,
			match: true,
		},
		{
			name: "port match specific",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				DstPort:   80,
			},
			dir:   Egress,
			hdr:   hdr,
			match: true,
		},
		{
			name: "port mismatch",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				DstPort:   443,
			},
			dir:   Egress,
			hdr:   hdr,
			match: false,
		},
		{
			name: "port wildcard 0 matches any",
			rule: Rule{
				Direction: Egress,
				Action:    Allow,
				DstPort:   0,
			},
			dir:   Egress,
			hdr:   hdr,
			match: true,
		},
		{
			name: "full rule match with all fields",
			rule: Rule{
				Direction: Egress,
				Action:    Deny,
				Protocol:  6,
				SrcCIDR:   *subnet,
				DstCIDR: func() net.IPNet {
					_, n, _ := net.ParseCIDR("192.168.1.0/24")
					return *n
				}(),
				SrcPort: 12345,
				DstPort: 80,
				Comment: "block outgoing HTTP",
			},
			dir:   Egress,
			hdr:   hdr,
			match: true,
		},
		{
			name: "full rule mismatch on one field",
			rule: Rule{
				Direction: Egress,
				Action:    Deny,
				Protocol:  6,
				SrcCIDR:   *subnet,
				DstCIDR: func() net.IPNet {
					_, n, _ := net.ParseCIDR("192.168.1.0/24")
					return *n
				}(),
				SrcPort: 12345,
				DstPort: 443, // mismatch: hdr has 80
			},
			dir:   Egress,
			hdr:   hdr,
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := tt.rule.Matches(tt.dir, tt.hdr)
			assert.Equal(t, tt.match, got)
		})
	}
}
