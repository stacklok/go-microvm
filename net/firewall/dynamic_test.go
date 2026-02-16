// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicRules_AddAndMatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	dr := NewDynamicRules()
	dr.now = func() time.Time { return now }

	_, cidr, _ := net.ParseCIDR("93.184.216.34/32")
	dr.Add(Rule{
		Direction: Egress,
		Action:    Allow,
		Protocol:  6,
		DstCIDR:   *cidr,
		DstPort:   443,
	}, 60*time.Second)

	assert.Equal(t, 1, dr.Len())

	hdr := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{93, 184, 216, 34},
		Protocol: 6,
		SrcPort:  54321,
		DstPort:  443,
	}

	action, ok := dr.Match(Egress, hdr)
	require.True(t, ok)
	assert.Equal(t, Allow, action)
}

func TestDynamicRules_NoMatch(t *testing.T) {
	t.Parallel()

	dr := NewDynamicRules()

	_, cidr, _ := net.ParseCIDR("93.184.216.34/32")
	dr.Add(Rule{
		Direction: Egress,
		Action:    Allow,
		Protocol:  6,
		DstCIDR:   *cidr,
		DstPort:   443,
	}, 60*time.Second)

	// Different destination port.
	hdr := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{93, 184, 216, 34},
		Protocol: 6,
		SrcPort:  54321,
		DstPort:  80,
	}

	_, ok := dr.Match(Egress, hdr)
	assert.False(t, ok)
}

func TestDynamicRules_Expiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	dr := NewDynamicRules()
	dr.now = func() time.Time { return now }

	_, cidr, _ := net.ParseCIDR("93.184.216.34/32")
	dr.Add(Rule{
		Direction: Egress,
		Action:    Allow,
		DstCIDR:   *cidr,
	}, 30*time.Second)

	hdr := &PacketHeader{
		DstIP:    [4]byte{93, 184, 216, 34},
		Protocol: 6,
		SrcPort:  54321,
		DstPort:  443,
	}

	// Still valid.
	_, ok := dr.Match(Egress, hdr)
	assert.True(t, ok)

	// Advance past expiry.
	now = now.Add(31 * time.Second)

	// Expired entry should not match.
	_, ok = dr.Match(Egress, hdr)
	assert.False(t, ok)
}

func TestDynamicRules_Sweep(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	dr := NewDynamicRules()
	dr.now = func() time.Time { return now }

	_, cidr1, _ := net.ParseCIDR("1.2.3.4/32")
	_, cidr2, _ := net.ParseCIDR("5.6.7.8/32")

	dr.Add(Rule{Direction: Egress, Action: Allow, DstCIDR: *cidr1}, 10*time.Second)
	dr.Add(Rule{Direction: Egress, Action: Allow, DstCIDR: *cidr2}, 60*time.Second)
	assert.Equal(t, 2, dr.Len())

	// Advance past first entry's expiry but not second.
	now = now.Add(11 * time.Second)
	dr.Sweep()

	assert.Equal(t, 1, dr.Len())

	// The surviving rule should still match.
	hdr := &PacketHeader{DstIP: [4]byte{5, 6, 7, 8}, Protocol: 6}
	_, ok := dr.Match(Egress, hdr)
	assert.True(t, ok)

	// The swept rule should not.
	hdr2 := &PacketHeader{DstIP: [4]byte{1, 2, 3, 4}, Protocol: 6}
	_, ok = dr.Match(Egress, hdr2)
	assert.False(t, ok)
}

func TestDynamicRules_Deduplication(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	dr := NewDynamicRules()
	dr.now = func() time.Time { return now }

	_, cidr, _ := net.ParseCIDR("93.184.216.34/32")
	rule := Rule{
		Direction: Egress,
		Action:    Allow,
		Protocol:  6,
		DstCIDR:   *cidr,
		DstPort:   443,
	}

	dr.Add(rule, 60*time.Second)
	dr.Add(rule, 60*time.Second) // duplicate — should extend, not add
	assert.Equal(t, 1, dr.Len())

	// Adding with longer TTL should extend expiry.
	dr.Add(rule, 120*time.Second)
	assert.Equal(t, 1, dr.Len())
}

func TestDynamicRules_Capacity(t *testing.T) {
	t.Parallel()

	dr := NewDynamicRules()
	dr.maxRules = 5

	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	for i := range 10 {
		dr.Add(Rule{
			Direction: Egress,
			Action:    Allow,
			DstCIDR:   *cidr,
			DstPort:   uint16(i + 1), // unique ports to avoid dedup
		}, time.Minute)
	}

	// Should be capped at 5.
	assert.Equal(t, 5, dr.Len())
}

func TestDynamicRules_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	dr := NewDynamicRules()
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")

	var wg sync.WaitGroup
	for i := range 100 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			dr.Add(Rule{
				Direction: Egress,
				Action:    Allow,
				DstCIDR:   *cidr,
				DstPort:   uint16(n),
			}, time.Minute)
		}(i)
	}

	// Concurrently read while writing.
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hdr := &PacketHeader{DstIP: [4]byte{10, 1, 2, 3}, Protocol: 6, DstPort: 80}
			dr.Match(Egress, hdr)
		}()
	}

	wg.Wait()
	assert.Equal(t, 100, dr.Len())
}
