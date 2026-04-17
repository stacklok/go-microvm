// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockDNSHook is a configurable DNSHook for testing relay DNS interception.
type mockDNSHook struct {
	egressResult InterceptResult
	ingressCalls atomic.Int32
}

func (m *mockDNSHook) HandleEgress(_ []byte, _ *PacketHeader) InterceptResult {
	return m.egressResult
}

func (m *mockDNSHook) HandleIngress(_ []byte, _ *PacketHeader) {
	m.ingressCalls.Add(1)
}

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

func TestRelay_RejectsOversizedLengthPrefix(t *testing.T) {
	t.Parallel()

	filter := NewFilter(nil, Allow)
	relay := NewRelay(filter)

	vmApp, vmRelay := net.Pipe()
	netRelay, _ := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Write a 4-byte big-endian length prefix claiming a 2 MiB frame —
	// well above maxFrameSize. Do not send any payload.
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 2*1024*1024)
	_, err := vmApp.Write(lenBuf[:])
	require.NoError(t, err)

	// The relay must terminate with a protocol-violation error rather
	// than attempt a multi-MiB allocation and hang on ReadFull.
	select {
	case err := <-errCh:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not terminate on oversized length prefix")
	}
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

func TestRelay_DropsNonIPv4UnderDenyDefault(t *testing.T) {
	t.Parallel()

	// Deny-default with no DNS hook. IPv6 (and any other non-IPv4, non-ARP
	// EtherType) would previously pass through as "hdr == nil" without
	// being checked against the filter. Callers who set FirewallDefault
	// Deny expect a closed egress; honor that for v6 frames.
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

	// Build a minimal IPv6-tagged frame (EtherType 0x86DD).
	v6Frame := make([]byte, 60)
	binary.BigEndian.PutUint16(v6Frame[12:14], 0x86DD)

	// Send the v6 frame first; it must be dropped.
	_, err := vmApp.Write(buildPrefixedFrame(v6Frame))
	require.NoError(t, err)

	// Follow with an ARP frame; it must still pass (existing guarantee).
	arpFrame := make([]byte, 42)
	binary.BigEndian.PutUint16(arpFrame[12:14], 0x0806)
	_, err = vmApp.Write(buildPrefixedFrame(arpFrame))
	require.NoError(t, err)

	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, arpFrame, got, "ARP should still pass under deny-default")

	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())
	assert.Equal(t, uint64(1), m.FramesDropped.Load(), "v6 frame must have been dropped")

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

func TestNewRelayWithDNSHook_InterceptForward(t *testing.T) {
	t.Parallel()

	hook := &mockDNSHook{
		egressResult: InterceptResult{Action: InterceptForward},
	}
	filter := NewFilter(nil, Allow)
	relay := NewRelayWithDNSHook(filter, hook)

	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Build a DNS egress frame (UDP port 53).
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{192, 168, 127, 1}
	dnsFrame := buildEthIPv4Frame(srcIP, dstIP, 17, 40000, 53, 5)

	_, err := vmApp.Write(buildPrefixedFrame(dnsFrame))
	require.NoError(t, err)

	// InterceptForward: frame passes through normal filtering and arrives.
	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, dnsFrame, got)

	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())
	assert.Equal(t, uint64(0), m.FramesDropped.Load())

	cancel()
	<-errCh
}

func TestRelay_DNSHook_InterceptDrop(t *testing.T) {
	t.Parallel()

	hook := &mockDNSHook{
		egressResult: InterceptResult{Action: InterceptDrop},
	}
	filter := NewFilter(nil, Allow)
	relay := NewRelayWithDNSHook(filter, hook)

	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// DNS frame should be dropped.
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{192, 168, 127, 1}
	dnsFrame := buildEthIPv4Frame(srcIP, dstIP, 17, 40000, 53, 5)
	_, err := vmApp.Write(buildPrefixedFrame(dnsFrame))
	require.NoError(t, err)

	// Non-DNS TCP frame should pass through.
	tcpFrame := buildEthIPv4Frame(srcIP, [4]byte{93, 184, 216, 34}, 6, 54321, 80, 5)
	_, err = vmApp.Write(buildPrefixedFrame(tcpFrame))
	require.NoError(t, err)

	// Only the TCP frame should arrive on the network side.
	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, tcpFrame, got)

	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())
	assert.Equal(t, uint64(1), m.FramesDropped.Load())

	cancel()
	<-errCh
}

func TestRelay_DNSHook_InterceptRespond(t *testing.T) {
	t.Parallel()

	// Build a fake NXDOMAIN response frame.
	nxdomainFrame := []byte("fake-nxdomain-response")
	hook := &mockDNSHook{
		egressResult: InterceptResult{
			Action:        InterceptRespond,
			ResponseFrame: nxdomainFrame,
		},
	}
	filter := NewFilter(nil, Allow)
	relay := NewRelayWithDNSHook(filter, hook)

	vmApp, vmRelay := net.Pipe()
	netRelay, _ := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Send a DNS egress frame.
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{192, 168, 127, 1}
	dnsFrame := buildEthIPv4Frame(srcIP, dstIP, 17, 40000, 53, 5)
	_, err := vmApp.Write(buildPrefixedFrame(dnsFrame))
	require.NoError(t, err)

	// The NXDOMAIN response should be written back to the VM side.
	got := readPrefixedFrame(t, vmApp)
	assert.Equal(t, nxdomainFrame, got)

	m := relay.Metrics()
	assert.Equal(t, uint64(0), m.FramesForwarded.Load())
	assert.Equal(t, uint64(1), m.FramesDropped.Load())

	cancel()
	<-errCh
}

func TestRelay_DNSHook_IngressSnooping(t *testing.T) {
	t.Parallel()

	hook := &mockDNSHook{
		egressResult: InterceptResult{Action: InterceptForward},
	}
	filter := NewFilter(nil, Allow)
	relay := NewRelayWithDNSHook(filter, hook)

	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Build an ingress DNS response frame (from port 53).
	srcIP := [4]byte{192, 168, 127, 1}
	dstIP := [4]byte{10, 0, 0, 1}
	dnsResponseFrame := buildEthIPv4Frame(srcIP, dstIP, 17, 53, 40000, 5)

	_, err := netApp.Write(buildPrefixedFrame(dnsResponseFrame))
	require.NoError(t, err)

	// Frame should be forwarded to VM.
	got := readPrefixedFrame(t, vmApp)
	assert.Equal(t, dnsResponseFrame, got)

	// HandleIngress should have been called.
	assert.Equal(t, int32(1), hook.ingressCalls.Load())

	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())

	cancel()
	<-errCh
}

func TestRelay_DNSHook_DropsIPv6(t *testing.T) {
	t.Parallel()

	hook := &mockDNSHook{
		egressResult: InterceptResult{Action: InterceptForward},
	}
	filter := NewFilter(nil, Allow)
	relay := NewRelayWithDNSHook(filter, hook)

	vmApp, vmRelay := net.Pipe()
	netRelay, netApp := net.Pipe()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- relay.Run(ctx, vmRelay, netRelay)
	}()

	// Build an IPv6 frame (EtherType 0x86DD). ParseHeaders returns nil for this.
	ipv6Frame := make([]byte, 60)
	binary.BigEndian.PutUint16(ipv6Frame[12:14], 0x86DD)

	_, err := vmApp.Write(buildPrefixedFrame(ipv6Frame))
	require.NoError(t, err)

	// Send a valid IPv4 frame afterward so we can synchronize.
	srcIP := [4]byte{10, 0, 0, 1}
	dstIP := [4]byte{93, 184, 216, 34}
	ipv4Frame := buildEthIPv4Frame(srcIP, dstIP, 6, 54321, 80, 5)
	_, err = vmApp.Write(buildPrefixedFrame(ipv4Frame))
	require.NoError(t, err)

	// Only the IPv4 frame should arrive; IPv6 should be dropped.
	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, ipv4Frame, got)

	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())
	assert.Equal(t, uint64(1), m.FramesDropped.Load())

	cancel()
	<-errCh
}

func TestRelay_DNSHook_AllowsARP(t *testing.T) {
	t.Parallel()

	hook := &mockDNSHook{
		egressResult: InterceptResult{Action: InterceptForward},
	}
	filter := NewFilter(nil, Allow)
	relay := NewRelayWithDNSHook(filter, hook)

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
	arpFrame[14] = 0x00
	arpFrame[15] = 0x01

	_, err := vmApp.Write(buildPrefixedFrame(arpFrame))
	require.NoError(t, err)

	// ARP should pass through even with DNS hook active.
	got := readPrefixedFrame(t, netApp)
	assert.Equal(t, arpFrame, got)

	m := relay.Metrics()
	assert.Equal(t, uint64(1), m.FramesForwarded.Load())
	assert.Equal(t, uint64(0), m.FramesDropped.Load())

	cancel()
	<-errCh
}
