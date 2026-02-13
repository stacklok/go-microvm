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
	"sync/atomic"

	"golang.org/x/sync/errgroup"
)

// Metrics holds atomic counters for relay traffic statistics.
type Metrics struct {
	FramesForwarded atomic.Uint64
	FramesDropped   atomic.Uint64
	BytesForwarded  atomic.Uint64
}

// Relay sits between the VM and the network provider, filtering frames
// through a [Filter] and collecting traffic metrics.
type Relay struct {
	filter  *Filter
	metrics *Metrics
}

// NewRelay creates a relay that applies the given filter to all traffic.
func NewRelay(filter *Filter) *Relay {
	return &Relay{
		filter:  filter,
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

		// Write length prefix + frame.
		binary.BigEndian.PutUint32(lenBuf[:], frameLen)
		if _, err := dst.Write(lenBuf[:]); err != nil {
			return r.wrapError(ctx, fmt.Errorf("write length prefix: %w", err))
		}
		if _, err := dst.Write(frameBuf); err != nil {
			return r.wrapError(ctx, fmt.Errorf("write frame payload: %w", err))
		}
	}
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
