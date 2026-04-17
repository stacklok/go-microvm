// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

// maxFrameSize bounds the length prefix the relay will accept from either
// peer. Legitimate traffic at the topology MTU sits well under 64 KiB —
// this cap catches corrupt or malicious length prefixes that would
// otherwise trigger multi-GiB allocations in the subsequent make/ReadFull.
const maxFrameSize = 65535

// InterceptAction tells the relay what to do with a DNS frame.
type InterceptAction uint8

const (
	// InterceptForward lets the frame continue through normal filtering.
	InterceptForward InterceptAction = iota
	// InterceptDrop silently drops the frame.
	InterceptDrop
	// InterceptRespond drops the original frame and sends a response back.
	InterceptRespond
)

// InterceptResult is returned by DNSHook.HandleEgress to control frame handling.
type InterceptResult struct {
	Action        InterceptAction
	ResponseFrame []byte // only set for InterceptRespond
}

// DNSHook is called by the relay for DNS frames before normal filtering.
// Implementations intercept DNS queries (egress) and snoop DNS responses
// (ingress) to implement policy-based egress restrictions.
type DNSHook interface {
	// HandleEgress is called for outbound UDP packets to port 53.
	HandleEgress(frame []byte, hdr *PacketHeader) InterceptResult
	// HandleIngress is called for inbound UDP packets from port 53.
	HandleIngress(frame []byte, hdr *PacketHeader)
}

// Metrics holds atomic counters for relay traffic statistics.
type Metrics struct {
	FramesForwarded atomic.Uint64
	FramesDropped   atomic.Uint64
	BytesForwarded  atomic.Uint64
}

// Relay sits between the VM and the network provider, filtering frames
// through a [Filter] and collecting traffic metrics. An optional DNSHook
// intercepts DNS traffic for egress policy enforcement.
type Relay struct {
	filter    *Filter
	dnsHook   DNSHook
	metrics   *Metrics
	vmWriteMu sync.Mutex // serializes writes to vmConn when dnsHook is set
}

// NewRelay creates a relay that applies the given filter to all traffic.
func NewRelay(filter *Filter) *Relay {
	return &Relay{
		filter:  filter,
		metrics: &Metrics{},
	}
}

// NewRelayWithDNSHook creates a relay with a DNS interceptor hook.
func NewRelayWithDNSHook(filter *Filter, hook DNSHook) *Relay {
	return &Relay{
		filter:  filter,
		dnsHook: hook,
		metrics: &Metrics{},
	}
}

// Metrics returns the traffic counters for this relay.
func (r *Relay) Metrics() *Metrics {
	return r.metrics
}

// Run starts two goroutines to relay frames between the VM and the
// network connection, applying the firewall filter to each frame.
//
// The wire format is the gvproxy/libkrun protocol: each Ethernet frame
// is preceded by a 4-byte big-endian length prefix on a SOCK_STREAM
// Unix socket.
//
// Run blocks until ctx is cancelled or an I/O error occurs, then closes
// both connections and returns the first error.
func (r *Relay) Run(ctx context.Context, vmConn, netConn net.Conn) error {
	g, gctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		return r.forward(gctx, vmConn, netConn, Egress)
	})

	g.Go(func() error {
		return r.forward(gctx, netConn, vmConn, Ingress)
	})

	// When the context is cancelled or a goroutine returns an error,
	// close both connections to unblock any pending reads.
	go func() {
		<-gctx.Done()
		_ = vmConn.Close()
		_ = netConn.Close()
	}()

	return g.Wait()
}

// forward reads length-prefixed frames from src, runs them through the
// filter, and writes allowed frames to dst.
func (r *Relay) forward(ctx context.Context, src, dst net.Conn, dir Direction) error {
	reader := bufio.NewReaderSize(src, 64*1024)
	var lenBuf [4]byte
	var frameBuf []byte

	for {
		// Read the 4-byte big-endian length prefix.
		if _, err := io.ReadFull(reader, lenBuf[:]); err != nil {
			return r.wrapError(ctx, fmt.Errorf("read length prefix: %w", err))
		}

		frameLen := binary.BigEndian.Uint32(lenBuf[:])
		if frameLen == 0 {
			continue
		}
		if frameLen > maxFrameSize {
			return r.wrapError(ctx, fmt.Errorf(
				"frame length %d exceeds maximum %d: peer protocol violation",
				frameLen, maxFrameSize))
		}

		// Grow the frame buffer if needed, reuse otherwise.
		if uint32(cap(frameBuf)) < frameLen {
			frameBuf = make([]byte, frameLen)
		}
		frameBuf = frameBuf[:frameLen]

		if _, err := io.ReadFull(reader, frameBuf); err != nil {
			return r.wrapError(ctx, fmt.Errorf("read frame payload: %w", err))
		}

		// Parse and filter.
		hdr := ParseHeaders(frameBuf)

		// DNS interception: egress queries and ingress responses.
		if r.dnsHook != nil && hdr != nil && hdr.Protocol == 17 {
			if dir == Egress && hdr.DstPort == 53 {
				result := r.dnsHook.HandleEgress(frameBuf, hdr)
				switch result.Action {
				case InterceptDrop:
					r.metrics.FramesDropped.Add(1)
					continue
				case InterceptRespond:
					// Write NXDOMAIN response back to VM under
					// the vmWriteMu to avoid interleaving with
					// ingress writes to the same connection.
					r.metrics.FramesDropped.Add(1)
					if err := r.writeVM(src, result.ResponseFrame); err != nil {
						return r.wrapError(ctx, fmt.Errorf("write NXDOMAIN response: %w", err))
					}
					continue
				}
				// InterceptForward: fall through to normal filtering.
			}
			if dir == Ingress && hdr.SrcPort == 53 {
				// Snoop response to learn IP mappings — fire-and-forget.
				r.dnsHook.HandleIngress(frameBuf, hdr)
				// Always fall through to normal filtering.
			}
		}

		// Non-IPv4 frames return hdr == nil from ParseHeaders. Under a
		// DNS hook or a deny-default filter, drop them (except ARP) so
		// that IPv6 and exotic EtherTypes cannot bypass the egress policy.
		// With neither, non-IPv4 frames pass through as before (needed
		// for basic network bootstrapping on allow-default setups).
		if hdr == nil && (r.dnsHook != nil || r.filter.defaultAction == Deny) {
			if len(frameBuf) >= 14 {
				etherType := binary.BigEndian.Uint16(frameBuf[12:14])
				if etherType != 0x0806 { // not ARP
					r.metrics.FramesDropped.Add(1)
					continue
				}
			}
		}

		if hdr != nil {
			verdict := r.filter.Verdict(dir, hdr)
			if verdict == Deny {
				r.metrics.FramesDropped.Add(1)
				slog.Debug("frame dropped",
					"dir", dir,
					"proto", hdr.Protocol,
					"src_port", hdr.SrcPort,
					"dst_port", hdr.DstPort,
				)
				continue
			}
		}
		// Non-IPv4 (hdr == nil) or Allow: forward the frame.
		// Increment metrics before writing so they are visible to readers
		// as soon as the data is consumed from the pipe.
		r.metrics.FramesForwarded.Add(1)
		r.metrics.BytesForwarded.Add(uint64(frameLen))

		// Write length prefix + frame. For ingress (writing to vmConn),
		// use the vmWriteMu to serialize with NXDOMAIN response writes.
		if dir == Ingress && r.dnsHook != nil {
			if err := r.writeVM(dst, frameBuf); err != nil {
				return r.wrapError(ctx, fmt.Errorf("write frame: %w", err))
			}
		} else {
			binary.BigEndian.PutUint32(lenBuf[:], frameLen)
			if _, err := dst.Write(lenBuf[:]); err != nil {
				return r.wrapError(ctx, fmt.Errorf("write length prefix: %w", err))
			}
			if _, err := dst.Write(frameBuf); err != nil {
				return r.wrapError(ctx, fmt.Errorf("write frame payload: %w", err))
			}
		}
	}
}

// writeVM writes a length-prefixed frame to the VM connection under the
// vmWriteMu to prevent interleaving between the egress goroutine
// (NXDOMAIN responses) and the ingress goroutine (forwarded frames).
func (r *Relay) writeVM(conn net.Conn, frame []byte) error {
	r.vmWriteMu.Lock()
	defer r.vmWriteMu.Unlock()

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(frame)))
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := conn.Write(frame)
	return err
}

// wrapError returns ctx.Err() if the context is done, otherwise returns
// the original error. This prevents reporting I/O errors caused by
// connection closure during shutdown.
func (r *Relay) wrapError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
