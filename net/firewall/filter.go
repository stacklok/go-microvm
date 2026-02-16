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
//
// When dynamic rules are configured, they are checked after static rules
// but before the default action. This allows DNS-snooped IPs to be
// permitted without static rules for every possible IP.
type Filter struct {
	rules         []Rule
	defaultAction Action
	conntrack     *ConnTracker
	dynamicRules  *DynamicRules
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

// NewFilterWithDynamic creates a filter with static rules, a default action,
// and a dynamic rule set for time-limited rules (e.g. from DNS snooping).
func NewFilterWithDynamic(rules []Rule, defaultAction Action, dr *DynamicRules) *Filter {
	return &Filter{
		rules:         rules,
		defaultAction: defaultAction,
		conntrack:     NewConnTracker(),
		dynamicRules:  dr,
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

	// Walk static rules in order; first match wins.
	for i := range f.rules {
		if f.rules[i].Matches(dir, hdr) {
			if f.rules[i].Action == Allow {
				f.conntrack.Track(dir, hdr)
			}
			return f.rules[i].Action
		}
	}

	// Check dynamic rules (e.g. DNS-snooped IPs) before default action.
	if f.dynamicRules != nil {
		if action, ok := f.dynamicRules.Match(dir, hdr); ok {
			if action == Allow {
				f.conntrack.Track(dir, hdr)
			}
			return action
		}
	}

	return f.defaultAction
}

// StartExpiry starts a background goroutine that periodically sweeps
// expired conntrack entries and dynamic rules. It stops when ctx is
// cancelled.
func (f *Filter) StartExpiry(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(defaultExpiryInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				f.conntrack.sweep()
				if f.dynamicRules != nil {
					f.dynamicRules.Sweep()
				}
			}
		}
	}()
}
