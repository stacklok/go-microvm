// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildPrefixedFrame constructs a wire-format frame: 4-byte BE length prefix
// followed by a raw Ethernet frame.
func buildPrefixedFrame(frame []byte) []byte {
	buf := make([]byte, 4+len(frame))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(frame)))
	copy(buf[4:], frame)
	return buf
}

// readPrefixedFrame reads a single length-prefixed frame from a connection.
func readPrefixedFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	var lenBuf [4]byte
	_, err := io.ReadFull(conn, lenBuf[:])
	require.NoError(t, err, "reading length prefix")

	frameLen := binary.BigEndian.Uint32(lenBuf[:])
	frame := make([]byte, frameLen)
	_, err = io.ReadFull(conn, frame)
	require.NoError(t, err, "reading frame payload")
	return frame
}

func TestRelay_EndToEnd(t *testing.T) {
	t.Parallel()

	// Allow-all filter.
	filter := NewFilter(nil, Allow)
	relay := NewRelay(filter)

	// Create two pipe pairs: one for the VM side, one for the network side.
	// vmApp <--pipe--> relay(vmConn) <--relay--> relay(netConn) <--pipe--> netApp
	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Build an egress frame (VM -> network).
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{93, 184, 216, 34}
	frame := buildEthIPv4Frame(srcIP, dstIP, 6, 54321, 80, 5)
	prefixed := buildPrefixedFrame(frame)

	// Write from VM side.
	_, err := vmApp.Write(prefixed)
	require.NoError(t, err)

	// Read from network side.
	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, frame, got)

	// Check metrics.
	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())
	assert.Equal(t, uint64(0), m.FramesDropped.Load())
	assert.Equal(t, uint64(len(frame)), m.BytesForwarded.Load())

	cancel()
	// Drain the error; should be context.Canceled.
	<-errCh
}

func TestRelay_DroppedFrame(t *testing.T) {
	t.Parallel()

	// Deny all egress TCP port 80.
	filter := NewFilter([]Rule{
		{Direction: Egress, Action: Deny, Protocol: 6, DstPort: 80},
	}, Allow)
	relay := NewRelay(filter)

	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Send a denied egress frame.
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{93, 184, 216, 34}
	deniedFrame := buildEthIPv4Frame(srcIP, dstIP, 6, 54321, 80, 5)

	// Also send an allowed egress frame (DNS over UDP port 53).
	allowedFrame := buildEthIPv4Frame(srcIP, [4]byte{8, 8, 8, 8}, 17, 40000, 53, 5)

	_, err := vmApp.Write(buildPrefixedFrame(deniedFrame))
	require.NoError(t, err)

	_, err = vmApp.Write(buildPrefixedFrame(allowedFrame))
	require.NoError(t, err)

	// We should only receive the allowed frame on the network side.
	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, allowedFrame, got)

	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())
	assert.Equal(t, uint64(1), m.FramesDropped.Load())

	cancel()
	<-errCh
}

func TestRelay_ARPPassthroughWithDenyAll(t *testing.T) {
	t.Parallel()

	// Deny-all default, no rules. ARP should still pass because it's non-IPv4.
	filter := NewFilter(nil, Deny)
	relay := NewRelay(filter)

	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Build an ARP frame (EtherType 0x0806).
	arpFrame := make([]byte, 42)
	binary.BigEndian.PutUint16(arpFrame[12:14], 0x0806)
	// Fill in some non-zero bytes so we can verify it arrives intact.
	arpFrame[14] = 0x00
	arpFrame[15] = 0x01

	_, err := vmApp.Write(buildPrefixedFrame(arpFrame))
	require.NoError(t, err)

	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, arpFrame, got)

	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())
	assert.Equal(t, uint64(0), m.FramesDropped.Load())

	cancel()
	<-errCh
}

func TestRelay_Metrics(t *testing.T) {
	t.Parallel()

	filter := NewFilter(nil, Allow)
	relay := NewRelay(filter)

	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{93, 184, 216, 34}

	// Send 3 frames from VM side.
	for i := range 3 {
		frame := buildEthIPv4Frame(srcIP, dstIP, 6, uint16(10000+i), 80, 5)
		_, err := vmApp.Write(buildPrefixedFrame(frame))
		require.NoError(t, err)
		_ = readPrefixedFrame(t, netApp)
	}

	m := relay.Metrics()
	assert.Equal(t, uint64(3), m.FramesForwarded.Load())
	assert.Equal(t, uint64(0), m.FramesDropped.Load())
	assert.Greater(t, m.BytesForwarded.Load(), uint64(0))

	cancel()
	<-errCh
}

func TestRelay_ContextCancellation(t *testing.T) {
	t.Parallel()

	filter := NewFilter(nil, Allow)
	relay := NewRelay(filter)

	vmApp, vmRelay := net.Pipe()
	netRelay, _ := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Cancel immediately.
	cancel()

	// Close the app side so the relay side sees EOF after context cancellation.
	_ = vmApp.Close()

	select {
	case err := <-errCh:
		// Should be context.Canceled or nil.
		if err != nil {
			assert.ErrorIs(t, err, context.Canceled)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not stop after context cancellation")
	}
}

func TestRelay_Bidirectional(t *testing.T) {
	t.Parallel()

	// Allow all traffic in both directions.
	filter := NewFilter(nil, Allow)
	relay := NewRelay(filter)

	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Egress: VM -> Network
	egressFrame := buildEthIPv4Frame(
		[4]byte{10, 0, 0, 1}, [4]byte{93, 184, 216, 34},
		6, 54321, 80, 5,
	)
	_, err := vmApp.Write(buildPrefixedFrame(egressFrame))
	require.NoError(t, err)
	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, egressFrame, got)

	// Ingress: Network -> VM
	ingressFrame := buildEthIPv4Frame(
		[4]byte{93, 184, 216, 34}, [4]byte{10, 0, 0, 1},
		6, 80, 54321, 5,
	)
	_, err = netApp.Write(buildPrefixedFrame(ingressFrame))
	require.NoError(t, err)
	got = readPrefixedFrame(t, vmApp)
	assert.Equal(t, ingressFrame, got)

	m := relay.Metrics()
	assert.Equal(t, uint64(2), m.FramesForwarded.Load())

	cancel()
	<-errCh
}
