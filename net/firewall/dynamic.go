// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"log/slog"
	"sync"
	"time"
)

const (
	// defaultMaxDynamicRules caps the number of entries to prevent
	// unbounded memory growth from DNS response floods.
	defaultMaxDynamicRules = 10000
)

// DynamicRules holds a thread-safe set of time-limited firewall rules.
// Rules are added dynamically (e.g. from DNS response snooping) and
// expire after their TTL. Expired entries are removed by Sweep().
type DynamicRules struct {
	mu       sync.RWMutex
	entries  []dynamicEntry
	maxRules int
	now      func() time.Time // injectable for testing
}

type dynamicEntry struct {
	rule      Rule
	expiresAt time.Time
}

// NewDynamicRules creates a new empty dynamic rule set.
func NewDynamicRules() *DynamicRules {
	return &DynamicRules{
		maxRules: defaultMaxDynamicRules,
		now:      time.Now,
	}
}

// Add inserts a rule that expires after ttl. If an identical rule already
// exists, its expiry is extended instead of creating a duplicate. New
// entries are rejected when the set is at capacity.
func (dr *DynamicRules) Add(rule Rule, ttl time.Duration) {
	expiresAt := dr.now().Add(ttl)

	dr.mu.Lock()
	defer dr.mu.Unlock()

	// Deduplicate: if the same rule exists, extend its expiry.
	for i := range dr.entries {
		if dr.entries[i].rule.Direction == rule.Direction &&
			dr.entries[i].rule.Protocol == rule.Protocol &&
			dr.entries[i].rule.DstCIDR.IP.Equal(rule.DstCIDR.IP) &&
			dr.entries[i].rule.DstPort == rule.DstPort &&
			dr.entries[i].rule.Action == rule.Action {
			if expiresAt.After(dr.entries[i].expiresAt) {
				dr.entries[i].expiresAt = expiresAt
			}
			return
		}
	}

	if len(dr.entries) >= dr.maxRules {
		slog.Warn("dynamic rules at capacity, dropping new rule",
			"capacity", dr.maxRules,
		)
		return
	}

	dr.entries = append(dr.entries, dynamicEntry{
		rule:      rule,
		expiresAt: expiresAt,
	})
}

// Match checks dynamic rules against the given packet. It returns the
// action and true if a non-expired rule matches, or false if none match.
func (dr *DynamicRules) Match(dir Direction, hdr *PacketHeader) (Action, bool) {
	now := dr.now()

	dr.mu.RLock()
	defer dr.mu.RUnlock()

	for i := range dr.entries {
		if now.After(dr.entries[i].expiresAt) {
			continue
		}
		if dr.entries[i].rule.Matches(dir, hdr) {
			return dr.entries[i].rule.Action, true
		}
	}
	return 0, false
}

// Sweep removes all expired entries.
func (dr *DynamicRules) Sweep() {
	now := dr.now()

	dr.mu.Lock()
	defer dr.mu.Unlock()

	n := 0
	for i := range dr.entries {
		if !now.After(dr.entries[i].expiresAt) {
			dr.entries[n] = dr.entries[i]
			n++
		}
	}
	// Zero tail to allow GC of Rule values in swept entries.
	for i := n; i < len(dr.entries); i++ {
		dr.entries[i] = dynamicEntry{}
	}
	dr.entries = dr.entries[:n]
}

// Len returns the number of entries (including expired ones not yet swept).
func (dr *DynamicRules) Len() int {
	dr.mu.RLock()
	defer dr.mu.RUnlock()
	return len(dr.entries)
}
