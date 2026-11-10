// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hyperv

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/stacklok/go-microvm/hypervisor"
)

// VsockListenerFunc opens a host listener for a guest vsock port.
type VsockListenerFunc func(port uint32) (net.Listener, error)

type vsockBridge struct {
	listeners []net.Listener
	closeOnce sync.Once
}

func startVsockBridges(
	ctx context.Context,
	ports []hypervisor.VsockPort,
	listenFn VsockListenerFunc,
) (*vsockBridge, error) {
	if len(ports) == 0 || listenFn == nil {
		return nil, nil
	}
	bridge := &vsockBridge{
		listeners: make([]net.Listener, 0, len(ports)),
	}
	for _, vp := range ports {
		if vp.SocketPath == "" || vp.Port == 0 {
			continue
		}
		listener, err := listenFn(vp.Port)
		if err != nil {
			bridge.Close()
			return nil, fmt.Errorf("listen on Hyper-V vsock port %d: %w", vp.Port, err)
		}
		if listener == nil {
			continue
		}
		bridge.listeners = append(bridge.listeners, listener)
		go serveVsockBridge(ctx, listener, vp.SocketPath)
	}
	return bridge, nil
}

func serveVsockBridge(ctx context.Context, listener net.Listener, unixSocketPath string) {
	for {
		guestConn, err := listener.Accept()
		if err != nil {
			return
		}
		go proxyVsockConn(ctx, guestConn, unixSocketPath)
	}
}

func proxyVsockConn(ctx context.Context, guestConn net.Conn, unixSocketPath string) {
	defer func() { _ = guestConn.Close() }()

	var dialer net.Dialer
	hostConn, err := dialer.DialContext(ctx, "unix", unixSocketPath)
	if err != nil {
		return
	}
	defer func() { _ = hostConn.Close() }()

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(hostConn, guestConn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(guestConn, hostConn)
		done <- struct{}{}
	}()
	select {
	case <-ctx.Done():
	case <-done:
	}
}

func (b *vsockBridge) Close() {
	if b == nil {
		return
	}
	b.closeOnce.Do(func() {
		for _, l := range b.listeners {
			_ = l.Close()
		}
	})
}
