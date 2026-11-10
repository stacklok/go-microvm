// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netcfg

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/mdlayher/vsock"
	"github.com/vishvananda/netlink"
)

const maxEthernetFrameSize = 65536

// BridgeStreamToPacket relays QEMU-framed Ethernet packets over a stream.
func BridgeStreamToPacket(ctx context.Context, stream io.ReadWriter, tap io.ReadWriter) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer closeReadWriters(stream, tap)

	errs := make(chan error, 2)
	go func() {
		errs <- copyPacketsToStream(stream, tap)
	}()
	go func() {
		errs <- copyStreamToPackets(stream, tap)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errs:
		return err
	}
}

func copyPacketsToStream(stream io.Writer, tap io.Reader) error {
	frame := make([]byte, maxEthernetFrameSize)
	header := make([]byte, 4)
	for {
		size, err := tap.Read(frame)
		if err != nil {
			return fmt.Errorf("read TAP frame: %w", err)
		}
		binary.BigEndian.PutUint32(header, uint32(size))
		if err := writeFull(stream, header); err != nil {
			return fmt.Errorf("write frame header: %w", err)
		}
		if err := writeFull(stream, frame[:size]); err != nil {
			return fmt.Errorf("write frame payload: %w", err)
		}
	}
}

func copyStreamToPackets(stream io.Reader, tap io.Writer) error {
	header := make([]byte, 4)
	frame := make([]byte, maxEthernetFrameSize)
	for {
		if _, err := io.ReadFull(stream, header); err != nil {
			return fmt.Errorf("read frame header: %w", err)
		}
		size := binary.BigEndian.Uint32(header)
		if size > maxEthernetFrameSize {
			return fmt.Errorf("frame size %d exceeds maximum %d", size, maxEthernetFrameSize)
		}
		payload := frame[:size]
		if _, err := io.ReadFull(stream, payload); err != nil {
			return fmt.Errorf("read frame payload: %w", err)
		}
		if err := writeFull(tap, payload); err != nil {
			return fmt.Errorf("write TAP frame: %w", err)
		}
	}
}

func writeFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		data = data[written:]
	}
	return nil
}

func closeReadWriters(readWriters ...io.ReadWriter) {
	for _, readWriter := range readWriters {
		if closer, ok := readWriter.(io.Closer); ok {
			_ = closer.Close()
		}
	}
}

// DialVsockStream connects to a host vsock port.
func DialVsockStream(port uint32) (net.Conn, error) {
	var lastErr error
	for attempt := range 20 {
		conn, err := vsock.Dial(vsock.Host, port, nil)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if attempt < 19 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	return nil, fmt.Errorf("dial host vsock port %d: %w", port, lastErr)
}

// StartHVSocketTAP creates a TAP and starts a host-vsock frame relay.
func StartHVSocketTAP(ctx context.Context, logger *slog.Logger, port uint32, ifName string) (func(), error) {
	if ifName == "" {
		ifName = "eth0"
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = ifName
	tapLink := &netlink.Tuntap{
		LinkAttrs:  attrs,
		Mode:       netlink.TUNTAP_MODE_TAP,
		Flags:      netlink.TUNTAP_NO_PI,
		NonPersist: true,
		Queues:     1,
	}
	if err := netlink.LinkAdd(tapLink); err != nil {
		return nil, fmt.Errorf("create TAP interface %q: %w", ifName, err)
	}
	if len(tapLink.Fds) != 1 {
		_ = netlink.LinkDel(tapLink)
		return nil, fmt.Errorf("create TAP interface %q: expected one queue, got %d", ifName, len(tapLink.Fds))
	}
	tap := tapLink.Fds[0]

	stream, err := DialVsockStream(port)
	if err != nil {
		_ = tap.Close()
		_ = netlink.LinkDel(tapLink)
		return nil, err
	}

	relayCtx, cancel := context.WithCancel(ctx)
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			cancel()
			_ = stream.Close()
			_ = tap.Close()
			_ = netlink.LinkDel(tapLink)
		})
	}
	go func() {
		err := BridgeStreamToPacket(relayCtx, stream, tap)
		if err != nil && !errors.Is(err, context.Canceled) && relayCtx.Err() == nil {
			logger.Error("Hyper-V socket network relay stopped", "error", err)
		}
		stop()
	}()

	return stop, nil
}
