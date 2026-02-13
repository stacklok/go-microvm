// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

const (
	// tcpFlowTTL is how long a TCP connection-tracking entry stays valid.
	tcpFlowTTL = 5 * time.Minute

	// defaultFlowTTL is the TTL for UDP and all other protocols.
	defaultFlowTTL = 30 * time.Second
)

// connKey uniquely identifies a directional network flow.
type connKey struct {
	protocol         uint8
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
}

// ConnTracker maintains a table of active network flows so that return
// traffic for an established connection can be allowed without an
// explicit rule.
type ConnTracker struct {
	mu    sync.RWMutex
	flows map[connKey]time.Time
	now   func() time.Time // injectable for testing; defaults to time.Now
}

// NewConnTracker creates a new connection tracker ready for use.
func NewConnTracker() *ConnTracker {
	return &ConnTracker{
		flows: make(map[connKey]time.Time),
		now:   time.Now,
	}
}

// Track records a flow so that its reverse (return) traffic can be
// recognised as established.
func (ct *ConnTracker) Track(_ Direction, hdr *PacketHeader) {
	key := connKey{
		protocol: hdr.Protocol,
		srcIP:    hdr.SrcIP,
		dstIP:    hdr.DstIP,
		srcPort:  hdr.SrcPort,
		dstPort:  hdr.DstPort,
	}

	ct.mu.Lock()
	ct.flows[key] = ct.now()
	ct.mu.Unlock()
}

// IsEstablished reports whether there is a tracked flow whose reverse
// direction matches the given header. This lets return traffic through
// without a matching rule.
func (ct *ConnTracker) IsEstablished(_ Direction, hdr *PacketHeader) bool {
	// Build the reverse key: swap src/dst IP and ports.
	reverse := connKey{
		protocol: hdr.Protocol,
		srcIP:    hdr.DstIP,
		dstIP:    hdr.SrcIP,
		srcPort:  hdr.DstPort,
		dstPort:  hdr.SrcPort,
	}

	ct.mu.RLock()
	ts, ok := ct.flows[reverse]
	ct.mu.RUnlock()

	if !ok {
		return false
	}

	ttl := flowTTL(hdr.Protocol)
	return ct.now().Sub(ts) <= ttl
}

// StartExpiry runs a background goroutine that periodically removes
// expired entries from the flow table. It stops when ctx is cancelled.
func (ct *ConnTracker) StartExpiry(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ct.sweep()
			}
		}
	}()
}

// Len returns the number of tracked flows. Intended for testing.
func (ct *ConnTracker) Len() int {
	ct.mu.RLock()
	defer ct.mu.RUnlock()
	return len(ct.flows)
}

// sweep removes all flow entries that have exceeded their TTL.
func (ct *ConnTracker) sweep() {
	now := ct.now()

	ct.mu.Lock()
	defer ct.mu.Unlock()

	for key, ts := range ct.flows {
		ttl := flowTTL(key.protocol)
		if now.Sub(ts) > ttl {
			delete(ct.flows, key)
		}
	}

	slog.Debug("conntrack sweep complete", "remaining", len(ct.flows))
}

// flowTTL returns the time-to-live for a connection-tracking entry based
// on the IP protocol number.
func flowTTL(proto uint8) time.Duration {
	if proto == 6 { // TCP
		return tcpFlowTTL
	}
	return defaultFlowTTL
}
