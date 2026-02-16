// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseDNSQuery(t *testing.T) {
	t.Parallel()

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 0x1234},
		Question: []dns.Question{
			{Name: "api.github.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
	}
	payload, err := msg.Pack()
	require.NoError(t, err)

	txnID, qname, qtype, err := ParseDNSQuery(payload)
	require.NoError(t, err)
	assert.Equal(t, uint16(0x1234), txnID)
	assert.Equal(t, "api.github.com.", qname)
	assert.Equal(t, dns.TypeA, qtype)
}

func TestParseDNSQuery_Invalid(t *testing.T) {
	t.Parallel()

	_, _, _, err := ParseDNSQuery([]byte{0x00})
	assert.Error(t, err)
}

func TestParseDNSQuery_NoQuestion(t *testing.T) {
	t.Parallel()

	msg := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 1}}
	payload, err := msg.Pack()
	require.NoError(t, err)

	_, _, _, err = ParseDNSQuery(payload)
	assert.Error(t, err)
}

func TestBuildNXDOMAIN(t *testing.T) {
	t.Parallel()

	payload, err := BuildNXDOMAIN(0xABCD, "blocked.com.", dns.TypeA)
	require.NoError(t, err)

	var msg dns.Msg
	require.NoError(t, msg.Unpack(payload))

	assert.Equal(t, uint16(0xABCD), msg.Id)
	assert.True(t, msg.Response)
	assert.Equal(t, dns.RcodeNameError, msg.Rcode)
	require.Len(t, msg.Question, 1)
	assert.Equal(t, "blocked.com.", msg.Question[0].Name)
	assert.Equal(t, dns.TypeA, msg.Question[0].Qtype)
}

func TestBuildNXDOMAIN_EchoesQueryType(t *testing.T) {
	t.Parallel()

	payload, err := BuildNXDOMAIN(0x1234, "example.com.", dns.TypeAAAA)
	require.NoError(t, err)

	var msg dns.Msg
	require.NoError(t, msg.Unpack(payload))

	require.Len(t, msg.Question, 1)
	assert.Equal(t, dns.TypeAAAA, msg.Question[0].Qtype)
}

func TestParseDNSResponse(t *testing.T) {
	t.Parallel()

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 0x5678, Response: true},
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
		Answer: []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   net.ParseIP("93.184.216.34"),
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   net.ParseIP("93.184.216.35"),
			},
		},
	}
	payload, err := msg.Pack()
	require.NoError(t, err)

	qname, ips, ttl, err := ParseDNSResponse(payload)
	require.NoError(t, err)
	assert.Equal(t, "example.com.", qname)
	assert.Len(t, ips, 2)
	assert.Equal(t, "93.184.216.34", ips[0].String())
	assert.Equal(t, "93.184.216.35", ips[1].String())
	assert.Equal(t, uint32(60), ttl) // minimum TTL
}

func TestParseDNSResponse_NoARecords(t *testing.T) {
	t.Parallel()

	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 1, Response: true},
		Question: []dns.Question{
			{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		},
		Answer: []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "other.example.com.",
			},
		},
	}
	payload, err := msg.Pack()
	require.NoError(t, err)

	_, ips, ttl, err := ParseDNSResponse(payload)
	require.NoError(t, err)
	assert.Empty(t, ips)
	assert.Equal(t, uint32(0), ttl)
}
