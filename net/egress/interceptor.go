// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"log/slog"
	"net"
	"time"

	"github.com/stacklok/propolis/net/firewall"
)

const (
	// defaultMinTTL is the minimum TTL applied to dynamic rules, even
	// if the DNS response has a shorter TTL. This prevents excessive
	// rule churn from very short TTLs.
	defaultMinTTL = 60 * time.Second
)

// DNSInterceptor intercepts DNS traffic at the relay level to enforce
// an egress policy. Blocked queries receive NXDOMAIN responses; allowed
// responses are snooped to create dynamic firewall rules.
type DNSInterceptor struct {
	policy       *Policy
	dynamicRules *firewall.DynamicRules
	minTTL       time.Duration
	gatewayIP    [4]byte
}

// NewDNSInterceptor creates an interceptor with the given policy, dynamic
// rule set, and gateway IP. Only DNS responses from the gateway are
// snooped to prevent spoofed responses from creating dynamic rules.
// Dynamic rules created from DNS responses will have at least minTTL
// duration (use 0 for the default of 60 seconds).
func NewDNSInterceptor(policy *Policy, dr *firewall.DynamicRules, gatewayIP [4]byte) *DNSInterceptor {
	return &DNSInterceptor{
		policy:       policy,
		dynamicRules: dr,
		minTTL:       defaultMinTTL,
		gatewayIP:    gatewayIP,
	}
}

// HandleEgress processes an outbound DNS query frame. If the queried
// hostname is allowed by the policy, the frame is forwarded. Otherwise,
// an NXDOMAIN response frame is returned to the VM.
func (d *DNSInterceptor) HandleEgress(frame []byte, hdr *firewall.PacketHeader) firewall.InterceptResult {
	payload, err := ExtractUDPPayload(frame)
	if err != nil {
		slog.Debug("egress: dropping unparseable UDP frame", "error", err)
		return firewall.InterceptResult{Action: firewall.InterceptDrop}
	}

	txnID, qname, qtype, err := ParseDNSQuery(payload)
	if err != nil {
		slog.Debug("egress: dropping unparseable DNS query", "error", err)
		return firewall.InterceptResult{Action: firewall.InterceptDrop}
	}

	if d.policy.IsAllowed(qname) {
		slog.Debug("egress: DNS query allowed", "qname", qname)
		return firewall.InterceptResult{Action: firewall.InterceptForward}
	}

	// Blocked: craft NXDOMAIN response echoing the original query type.
	slog.Debug("egress: DNS query blocked", "qname", qname)
	nxPayload, err := BuildNXDOMAIN(txnID, qname, qtype)
	if err != nil {
		slog.Warn("egress: failed to build NXDOMAIN", "error", err)
		return firewall.InterceptResult{Action: firewall.InterceptDrop}
	}

	respFrame, err := BuildResponseFrame(frame, nxPayload)
	if err != nil {
		slog.Warn("egress: failed to build response frame", "error", err)
		return firewall.InterceptResult{Action: firewall.InterceptDrop}
	}

	return firewall.InterceptResult{
		Action:        firewall.InterceptRespond,
		ResponseFrame: respFrame,
	}
}

// HandleIngress snoops an inbound DNS response to learn IP mappings for
// allowed hostnames. For each A record in the response, a dynamic
// firewall rule is created with the TTL from the DNS record. Only
// responses from the gateway IP are processed to prevent spoofed
// responses from injecting dynamic rules.
func (d *DNSInterceptor) HandleIngress(frame []byte, hdr *firewall.PacketHeader) {
	if hdr == nil || hdr.SrcIP != d.gatewayIP {
		slog.Debug("ingress: ignoring DNS response from non-gateway source",
			"src_ip", hdr.SrcIP)
		return
	}

	payload, err := ExtractUDPPayload(frame)
	if err != nil {
		slog.Debug("ingress: failed to extract UDP payload", "error", err)
		return
	}

	qname, ips, ttlSec, err := ParseDNSResponse(payload)
	if err != nil {
		slog.Debug("ingress: failed to parse DNS response", "error", err)
		return
	}
	if len(ips) == 0 {
		return
	}

	if !d.policy.IsAllowed(qname) {
		return
	}

	ttl := time.Duration(ttlSec) * time.Second
	if ttl < d.minTTL {
		ttl = d.minTTL
	}

	ports, proto := d.policy.HostPorts(qname)

	// When protocol is unspecified, create rules for both TCP and UDP
	// so that callers who omit the protocol field get full connectivity
	// to the resolved IPs rather than TCP-only.
	var ruleProtos []uint8
	if proto == 0 {
		ruleProtos = []uint8{6, 17} // TCP + UDP
	} else {
		ruleProtos = []uint8{proto}
	}

	for _, ip := range ips {
		ip4 := ip.To4()
		if ip4 == nil {
			continue
		}

		cidr := net.IPNet{
			IP:   ip4,
			Mask: net.CIDRMask(32, 32),
		}

		for _, ruleProto := range ruleProtos {
			if len(ports) == 0 {
				d.dynamicRules.Add(firewall.Rule{
					Direction: firewall.Egress,
					Action:    firewall.Allow,
					Protocol:  ruleProto,
					DstCIDR:   cidr,
				}, ttl)
				slog.Debug("egress: dynamic rule added",
					"ip", ip4.String(),
					"proto", ruleProto,
					"ttl", ttl,
				)
			} else {
				for _, port := range ports {
					d.dynamicRules.Add(firewall.Rule{
						Direction: firewall.Egress,
						Action:    firewall.Allow,
						Protocol:  ruleProto,
						DstCIDR:   cidr,
						DstPort:   port,
					}, ttl)
					slog.Debug("egress: dynamic rule added",
						"ip", ip4.String(),
						"port", port,
						"proto", ruleProto,
						"ttl", ttl,
					)
				}
			}
		}
	}
}
