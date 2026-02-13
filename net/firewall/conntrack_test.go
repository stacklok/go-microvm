// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnTracker_TrackAndIsEstablished(t *testing.T) {
	t.Parallel()

	hdrEgress := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{192, 168, 1, 100},
		Protocol: 6,
		SrcPort:  12345,
		DstPort:  80,
	}

	// The reverse header (ingress return traffic).
	hdrIngress := &PacketHeader{
		SrcIP:    [4]byte{192, 168, 1, 100},
		DstIP:    [4]byte{10, 0, 0, 1},
		Protocol: 6,
		SrcPort:  80,
		DstPort:  12345,
	}

	tests := []struct {
		name        string
		trackDir    Direction
		trackHdr    *PacketHeader
		checkDir    Direction
		checkHdr    *PacketHeader
		established bool
	}{
		{
			name:        "track egress, check ingress reverse matches",
			trackDir:    Egress,
			trackHdr:    hdrEgress,
			checkDir:    Ingress,
			checkHdr:    hdrIngress,
			established: true,
		},
		{
			name:        "track ingress, check egress reverse matches",
			trackDir:    Ingress,
			trackHdr:    hdrIngress,
			checkDir:    Egress,
			checkHdr:    hdrEgress,
			established: true,
		},
		{
			name:     "no tracked flow, not established",
			trackDir: Egress,
			trackHdr: hdrEgress,
			checkDir: Ingress,
			checkHdr: &PacketHeader{
				SrcIP:    [4]byte{172, 16, 0, 1},
				DstIP:    [4]byte{10, 0, 0, 1},
				Protocol: 6,
				SrcPort:  80,
				DstPort:  12345,
			},
			established: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ct := NewConnTracker()
			ct.Track(tt.trackDir, tt.trackHdr)

			got := ct.IsEstablished(tt.checkDir, tt.checkHdr)
			assert.Equal(t, tt.established, got)
		})
	}
}

func TestConnTracker_TTLExpiry(t *testing.T) {
	t.Parallel()

	fakeNow := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name        string
		protocol    uint8
		advance     time.Duration
		established bool
	}{
		{
			name:        "TCP within TTL",
			protocol:    6,
			advance:     4 * time.Minute,
			established: true,
		},
		{
			name:        "TCP at TTL boundary",
			protocol:    6,
			advance:     5 * time.Minute,
			established: true,
		},
		{
			name:        "TCP beyond TTL",
			protocol:    6,
			advance:     5*time.Minute + time.Second,
			established: false,
		},
		{
			name:        "UDP within TTL",
			protocol:    17,
			advance:     25 * time.Second,
			established: true,
		},
		{
			name:        "UDP at TTL boundary",
			protocol:    17,
			advance:     30 * time.Second,
			established: true,
		},
		{
			name:        "UDP beyond TTL",
			protocol:    17,
			advance:     31 * time.Second,
			established: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			currentTime := fakeNow
			ct := NewConnTracker()
			ct.now = func() time.Time { return currentTime }

			egress := &PacketHeader{
				SrcIP:    [4]byte{10, 0, 0, 1},
				DstIP:    [4]byte{192, 168, 1, 100},
				Protocol: tt.protocol,
				SrcPort:  12345,
				DstPort:  80,
			}
			ingress := &PacketHeader{
				SrcIP:    [4]byte{192, 168, 1, 100},
				DstIP:    [4]byte{10, 0, 0, 1},
				Protocol: tt.protocol,
				SrcPort:  80,
				DstPort:  12345,
			}

			ct.Track(Egress, egress)

			// Advance the clock.
			currentTime = fakeNow.Add(tt.advance)

			got := ct.IsEstablished(Ingress, ingress)
			assert.Equal(t, tt.established, got)
		})
	}
}

func TestConnTracker_StartExpiry(t *testing.T) {
	t.Parallel()

	currentTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	ct := NewConnTracker()
	ct.now = func() time.Time { return currentTime }

	hdr := &PacketHeader{
		SrcIP:    [4]byte{10, 0, 0, 1},
		DstIP:    [4]byte{192, 168, 1, 100},
		Protocol: 17, // UDP, 30s TTL
		SrcPort:  5000,
		DstPort:  53,
	}

	ct.Track(Egress, hdr)
	require.Equal(t, 1, ct.Len())

	// Advance past the UDP TTL.
	currentTime = currentTime.Add(31 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run expiry with a very short interval so it fires quickly.
	ct.StartExpiry(ctx, 10*time.Millisecond)

	// Wait for the sweep to run.
	assert.Eventually(t, func() bool {
		return ct.Len() == 0
	}, 2*time.Second, 10*time.Millisecond, "expired entry should be swept")
}

func TestConnTracker_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	ct := NewConnTracker()
	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	wg.Add(goroutines * 2) // half tracking, half checking

	for i := range goroutines {
		// Tracker goroutine.
		go func(idx int) {
			defer wg.Done()
			for j := range iterations {
				hdr := &PacketHeader{
					SrcIP:    [4]byte{10, 0, byte(idx), byte(j)},
					DstIP:    [4]byte{192, 168, 1, 1},
					Protocol: 6,
					SrcPort:  uint16(10000 + j),
					DstPort:  80,
				}
				ct.Track(Egress, hdr)
			}
		}(i)

		// Checker goroutine.
		go func(idx int) {
			defer wg.Done()
			for j := range iterations {
				hdr := &PacketHeader{
					SrcIP:    [4]byte{192, 168, 1, 1},
					DstIP:    [4]byte{10, 0, byte(idx), byte(j)},
					Protocol: 6,
					SrcPort:  80,
					DstPort:  uint16(10000 + j),
				}
				// Just call it; we don't care about the result, only that
				// it doesn't race.
				ct.IsEstablished(Ingress, hdr)
			}
		}(i)
	}

	wg.Wait()
}
