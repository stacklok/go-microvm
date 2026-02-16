// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"fmt"
	"net"

	"github.com/miekg/dns"
)

// ParseDNSQuery extracts the transaction ID, question name, and query type
// from a DNS query payload (UDP payload, not including Ethernet/IP/UDP headers).
func ParseDNSQuery(payload []byte) (txnID uint16, qname string, qtype uint16, err error) {
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil {
		return 0, "", 0, fmt.Errorf("unpack DNS query: %w", err)
	}
	if len(msg.Question) == 0 {
		return 0, "", 0, fmt.Errorf("DNS query has no question section")
	}
	if len(msg.Question) > 1 {
		return 0, "", 0, fmt.Errorf("DNS query has %d questions, expected 1", len(msg.Question))
	}
	return msg.Id, msg.Question[0].Name, msg.Question[0].Qtype, nil
}

// BuildNXDOMAIN crafts a minimal DNS NXDOMAIN response payload for the
// given transaction ID, question name, and query type. The query type is
// echoed back in the question section to match the original query.
func BuildNXDOMAIN(txnID uint16, qname string, qtype uint16) ([]byte, error) {
	msg := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 txnID,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeNameError,
		},
		Question: []dns.Question{
			{Name: qname, Qtype: qtype, Qclass: dns.ClassINET},
		},
	}
	packed, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack NXDOMAIN response: %w", err)
	}
	return packed, nil
}

// ParseDNSResponse extracts the question name, A-record IPs, and minimum
// TTL from a DNS response payload.
func ParseDNSResponse(payload []byte) (qname string, ips []net.IP, ttl uint32, err error) {
	var msg dns.Msg
	if err := msg.Unpack(payload); err != nil {
		return "", nil, 0, fmt.Errorf("unpack DNS response: %w", err)
	}
	if len(msg.Question) > 0 {
		qname = msg.Question[0].Name
	}

	var minTTL uint32
	first := true
	for _, rr := range msg.Answer {
		a, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		ips = append(ips, a.A)
		if first || a.Hdr.Ttl < minTTL {
			minTTL = a.Hdr.Ttl
			first = false
		}
	}
	return qname, ips, minTTL, nil
}
