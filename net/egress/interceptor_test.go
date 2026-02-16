// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"encoding/binary"
	"net"
	"testing"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/net/firewall"
)

// buildDNSQueryFrame builds a complete Ethernet frame containing a DNS query.
func buildDNSQueryFrame(srcMAC, dstMAC [6]byte, srcIP, dstIP [4]byte, srcPort uint16, qname string) []byte {
	msg := &mdns.Msg{
		MsgHdr: mdns.MsgHdr{Id: 0x1234, RecursionDesired: true},
		Question: []mdns.Question{
			{Name: mdns.Fqdn(qname), Qtype: mdns.TypeA, Qclass: mdns.ClassINET},
		},
	}
	payload, _ := msg.Pack()
	return buildTestUDPFrame(srcMAC, dstMAC, srcIP, dstIP, srcPort, 53, payload)
}

// buildDNSResponseFrame builds a complete Ethernet frame containing a DNS response.
func buildDNSResponseFrame(srcMAC, dstMAC [6]byte, srcIP, dstIP [4]byte, dstPort uint16, qname string, ips []net.IP, ttl uint32) []byte {
	msg := &mdns.Msg{
		MsgHdr: mdns.MsgHdr{Id: 0x1234, Response: true},
		Question: []mdns.Question{
			{Name: mdns.Fqdn(qname), Qtype: mdns.TypeA, Qclass: mdns.ClassINET},
		},
	}
	for _, ip := range ips {
		msg.Answer = append(msg.Answer, &mdns.A{
			Hdr: mdns.RR_Header{Name: mdns.Fqdn(qname), Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttl},
			A:   ip,
		})
	}
	payload, _ := msg.Pack()
	return buildTestUDPFrame(srcMAC, dstMAC, srcIP, dstIP, 53, dstPort, payload)
}

var (
	testSrcMAC = [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	testDstMAC = [6]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}
	testSrcIP  = [4]byte{192, 168, 127, 2}
	testDstIP  = [4]byte{192, 168, 127, 1}
)

func TestDNSInterceptor_AllowedQuery(t *testing.T) {
	t.Parallel()

	policy := NewPolicy([]HostSpec{{Name: "api.github.com"}})
	dr := firewall.NewDynamicRules()
	interceptor := NewDNSInterceptor(policy, dr)

	frame := buildDNSQueryFrame(testSrcMAC, testDstMAC, testSrcIP, testDstIP, 12345, "api.github.com")
	hdr := firewall.ParseHeaders(frame)

	result := interceptor.HandleEgress(frame, hdr)
	assert.Equal(t, firewall.InterceptForward, result.Action)
}

func TestDNSInterceptor_BlockedQuery(t *testing.T) {
	t.Parallel()

	policy := NewPolicy([]HostSpec{{Name: "api.github.com"}})
	dr := firewall.NewDynamicRules()
	interceptor := NewDNSInterceptor(policy, dr)

	frame := buildDNSQueryFrame(testSrcMAC, testDstMAC, testSrcIP, testDstIP, 12345, "evil.com")
	hdr := firewall.ParseHeaders(frame)

	result := interceptor.HandleEgress(frame, hdr)
	assert.Equal(t, firewall.InterceptRespond, result.Action)
	assert.NotEmpty(t, result.ResponseFrame)

	// Verify the response is NXDOMAIN.
	respPayload, err := ExtractUDPPayload(result.ResponseFrame)
	require.NoError(t, err)

	var msg mdns.Msg
	require.NoError(t, msg.Unpack(respPayload))
	assert.Equal(t, mdns.RcodeNameError, msg.Rcode)
	assert.True(t, msg.Response)
}

func TestDNSInterceptor_WildcardAllowed(t *testing.T) {
	t.Parallel()

	policy := NewPolicy([]HostSpec{{Name: "*.docker.io"}})
	dr := firewall.NewDynamicRules()
	interceptor := NewDNSInterceptor(policy, dr)

	frame := buildDNSQueryFrame(testSrcMAC, testDstMAC, testSrcIP, testDstIP, 12345, "registry-1.docker.io")
	hdr := firewall.ParseHeaders(frame)

	result := interceptor.HandleEgress(frame, hdr)
	assert.Equal(t, firewall.InterceptForward, result.Action)
}

func TestDNSInterceptor_ResponseSnooping(t *testing.T) {
	t.Parallel()

	policy := NewPolicy([]HostSpec{{Name: "api.github.com", Ports: []uint16{443}}})
	dr := firewall.NewDynamicRules()
	interceptor := NewDNSInterceptor(policy, dr)

	ips := []net.IP{net.ParseIP("140.82.121.5"), net.ParseIP("140.82.121.6")}
	frame := buildDNSResponseFrame(testDstMAC, testSrcMAC, testDstIP, testSrcIP, 12345, "api.github.com", ips, 300)
	hdr := firewall.ParseHeaders(frame)

	interceptor.HandleIngress(frame, hdr)

	// Should have created dynamic rules for both IPs.
	assert.Equal(t, 2, dr.Len())

	// Verify that the rules match egress traffic to the IPs.
	hdr1 := &firewall.PacketHeader{
		DstIP:    [4]byte{140, 82, 121, 5},
		Protocol: 6,
		DstPort:  443,
	}
	action, ok := dr.Match(firewall.Egress, hdr1)
	require.True(t, ok)
	assert.Equal(t, firewall.Allow, action)

	// Wrong port should not match.
	hdr2 := &firewall.PacketHeader{
		DstIP:    [4]byte{140, 82, 121, 5},
		Protocol: 6,
		DstPort:  80,
	}
	_, ok = dr.Match(firewall.Egress, hdr2)
	assert.False(t, ok)
}

func TestDNSInterceptor_ResponseSnooping_AllPorts(t *testing.T) {
	t.Parallel()

	policy := NewPolicy([]HostSpec{{Name: "example.com"}})
	dr := firewall.NewDynamicRules()
	interceptor := NewDNSInterceptor(policy, dr)

	ips := []net.IP{net.ParseIP("93.184.216.34")}
	frame := buildDNSResponseFrame(testDstMAC, testSrcMAC, testDstIP, testSrcIP, 12345, "example.com", ips, 60)
	hdr := firewall.ParseHeaders(frame)

	interceptor.HandleIngress(frame, hdr)

	// Rule should match any port for TCP.
	hdr1 := &firewall.PacketHeader{
		DstIP:    [4]byte{93, 184, 216, 34},
		Protocol: 6,
		DstPort:  443,
	}
	action, ok := dr.Match(firewall.Egress, hdr1)
	require.True(t, ok)
	assert.Equal(t, firewall.Allow, action)
}

func TestDNSInterceptor_ResponseSnooping_NotAllowed(t *testing.T) {
	t.Parallel()

	policy := NewPolicy([]HostSpec{{Name: "allowed.com"}})
	dr := firewall.NewDynamicRules()
	interceptor := NewDNSInterceptor(policy, dr)

	// Response for a host not in the policy — should be ignored.
	ips := []net.IP{net.ParseIP("1.2.3.4")}
	frame := buildDNSResponseFrame(testDstMAC, testSrcMAC, testDstIP, testSrcIP, 12345, "notallowed.com", ips, 60)
	hdr := firewall.ParseHeaders(frame)

	interceptor.HandleIngress(frame, hdr)

	assert.Equal(t, 0, dr.Len())
}

func TestDNSInterceptor_ResponseNXDOMAINFrameFormat(t *testing.T) {
	t.Parallel()

	policy := NewPolicy([]HostSpec{{Name: "allowed.com"}})
	dr := firewall.NewDynamicRules()
	interceptor := NewDNSInterceptor(policy, dr)

	frame := buildDNSQueryFrame(testSrcMAC, testDstMAC, testSrcIP, testDstIP, 54321, "blocked.com")
	hdr := firewall.ParseHeaders(frame)

	result := interceptor.HandleEgress(frame, hdr)
	require.Equal(t, firewall.InterceptRespond, result.Action)

	// Verify the response frame is well-formed.
	respHdr := firewall.ParseHeaders(result.ResponseFrame)
	require.NotNil(t, respHdr)
	assert.Equal(t, uint8(17), respHdr.Protocol) // UDP
	assert.Equal(t, uint16(53), respHdr.SrcPort)
	assert.Equal(t, uint16(54321), respHdr.DstPort)

	// Verify IPs are swapped correctly.
	assert.Equal(t, testDstIP, respHdr.SrcIP)
	assert.Equal(t, testSrcIP, respHdr.DstIP)

	// Verify IP checksum.
	ipStart := 14
	ihl := int(result.ResponseFrame[ipStart]&0x0F) * 4
	cksum := ipChecksum(result.ResponseFrame[ipStart : ipStart+ihl])
	assert.Equal(t, uint16(0), cksum, "IP checksum should verify")

	// Verify MACs are swapped.
	assert.Equal(t, testSrcMAC[:], result.ResponseFrame[0:6])
	assert.Equal(t, testDstMAC[:], result.ResponseFrame[6:12])

	// Verify IP total length is correct.
	ipTotalLen := binary.BigEndian.Uint16(result.ResponseFrame[ipStart+2 : ipStart+4])
	expectedIPLen := uint16(ihl + 8 + len(result.ResponseFrame) - (ipStart + ihl + 8))
	assert.Equal(t, expectedIPLen, ipTotalLen)
}
