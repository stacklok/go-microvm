// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"context"
	"time"
)

const (
	// defaultExpiryInterval is how often the conntrack table is swept.
	defaultExpiryInterval = 30 * time.Second
)

// Filter evaluates packets against an ordered rule list with stateful
// connection tracking. Rules are evaluated in order and the first match
// wins. If no rule matches, the default action is applied.
type Filter struct {
	rules         []Rule
	defaultAction Action
	conntrack     *ConnTracker
}

// NewFilter creates a filter with the given rules and default action.
// A new connection tracker is allocated automatically.
func NewFilter(rules []Rule, defaultAction Action) *Filter {
	return &Filter{
		rules:         rules,
		defaultAction: defaultAction,
		conntrack:     NewConnTracker(),
	}
}

// Verdict determines whether a packet should be allowed or denied.
//
// The evaluation order is:
//  1. Connection tracking fast path -- if a reverse flow is already
//     tracked, the packet belongs to an established connection and is
//     allowed immediately.
//  2. Rule walk -- rules are checked in order. The first matching rule
//     wins. If the action is Allow, the flow is tracked so that return
//     traffic is recognised.
//  3. Default action -- returned when no rule matches.
func (f *Filter) Verdict(dir Direction, hdr *PacketHeader) Action {
	// Fast path: established connections are always allowed.
	if f.conntrack.IsEstablished(dir, hdr) {
		return Allow
	}

	// Walk rules in order; first match wins.
	for i := range f.rules {
		if f.rules[i].Matches(dir, hdr) {
			if f.rules[i].Action == Allow {
				f.conntrack.Track(dir, hdr)
			}
			return f.rules[i].Action
		}
	}

	return f.defaultAction
}

// StartExpiry starts the background conntrack entry expiry goroutine.
// It sweeps expired entries every 30 seconds and stops when ctx is
// cancelled.
func (f *Filter) StartExpiry(ctx context.Context) {
	f.conntrack.StartExpiry(ctx, defaultExpiryInterval)
}
