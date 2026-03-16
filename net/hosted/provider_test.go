// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hosted

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/go-microvm/internal/testutil"
	propnet "github.com/stacklok/go-microvm/net"
	"github.com/stacklok/go-microvm/net/firewall"
)

// freePort returns a TCP port that is currently available on localhost.
func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return uint16(port)
}

func TestProviderLifecycle(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	p := NewProvider()
	hostPort := freePort(t)

	err := p.Start(context.Background(), propnet.Config{
		LogDir: dir,
		Forwards: []propnet.PortForward{
			{Host: hostPort, Guest: 22},
		},
	})
	require.NoError(t, err)

	// Socket file should exist.
	sockPath := p.SocketPath()
	assert.Equal(t, filepath.Join(dir, socketName), sockPath)
	_, err = os.Stat(sockPath)
	assert.NoError(t, err, "socket file should exist after Start")

	// VirtualNetwork should be non-nil.
	assert.NotNil(t, p.VirtualNetwork(), "VirtualNetwork should be set after Start")

	// No firewall rules -> relay should be nil.
	assert.Nil(t, p.Relay(), "Relay should be nil without firewall rules")

	p.Stop()

	// Socket file should be cleaned up.
	_, err = os.Stat(sockPath)
	assert.True(t, os.IsNotExist(err), "socket file should be removed after Stop")
}

func TestVirtualNetworkNilBeforeStart(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	assert.Nil(t, p.VirtualNetwork(), "VirtualNetwork should be nil before Start")
}

func TestStaleSocketRemoval(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	stalePath := filepath.Join(dir, socketName)

	// Create a stale regular file where the socket should be.
	err := os.WriteFile(stalePath, []byte("stale"), 0o600)
	require.NoError(t, err)

	p := NewProvider()
	err = p.Start(context.Background(), propnet.Config{
		LogDir: dir,
	})
	require.NoError(t, err)
	defer p.Stop()

	// Start should have replaced the stale file with a real socket.
	_, err = os.Stat(stalePath)
	assert.NoError(t, err, "socket should exist")
}

func TestStopIdempotent(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	p := NewProvider()

	err := p.Start(context.Background(), propnet.Config{
		LogDir: dir,
	})
	require.NoError(t, err)

	// Calling Stop multiple times should not panic.
	p.Stop()
	p.Stop()
}

func TestStartAlreadyStarted(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	p := NewProvider()

	err := p.Start(context.Background(), propnet.Config{LogDir: dir})
	require.NoError(t, err)
	defer p.Stop()

	err = p.Start(context.Background(), propnet.Config{LogDir: dir})
	assert.Error(t, err, "second Start should fail")
	assert.Contains(t, err.Error(), "already started")
}

func TestRelayWithFirewallRules(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	p := NewProvider()

	err := p.Start(context.Background(), propnet.Config{
		LogDir: dir,
		FirewallRules: []firewall.Rule{
			{
				Direction: firewall.Egress,
				Action:    firewall.Allow,
				Protocol:  6, // TCP
				DstPort:   443,
				Comment:   "allow HTTPS",
			},
		},
		FirewallDefaultAction: firewall.Deny,
	})
	require.NoError(t, err)
	defer p.Stop()

	assert.NotNil(t, p.Relay(), "Relay should be set with firewall rules")
	assert.NotNil(t, p.VirtualNetwork())
}

func TestSocketAcceptsConnection(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	p := NewProvider()

	err := p.Start(context.Background(), propnet.Config{
		LogDir: dir,
	})
	require.NoError(t, err)
	defer p.Stop()

	// Dial the Unix socket — this should succeed because the accept
	// loop is running.
	conn, err := net.Dial("unix", p.SocketPath())
	require.NoError(t, err, "should be able to connect to the hosted socket")
	_ = conn.Close()
}

func TestPortForwardMap(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	p := NewProvider()
	hostPort := freePort(t)

	err := p.Start(context.Background(), propnet.Config{
		LogDir: dir,
		Forwards: []propnet.PortForward{
			{Host: hostPort, Guest: 22},
		},
	})
	require.NoError(t, err)
	defer p.Stop()

	// The forwarded host port should be listening.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", hostPort))
	require.NoError(t, err, "forwarded host port should be reachable")
	_ = conn.Close()
}

func TestProvider_StartWithEgressPolicy(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	p := NewProvider()

	err := p.Start(context.Background(), propnet.Config{
		LogDir: dir,
		EgressPolicy: &propnet.EgressPolicy{
			AllowedHosts: []propnet.EgressHost{
				{Name: "api.github.com", Ports: []uint16{443}, Protocol: 6},
			},
		},
	})
	require.NoError(t, err)
	defer p.Stop()

	// buildEgressRelay should have created a relay with a DNS hook.
	assert.NotNil(t, p.Relay(), "Relay should be non-nil with EgressPolicy")
	assert.NotNil(t, p.VirtualNetwork())
}

func TestProvider_StartWithEgressPolicy_ImplicitRules(t *testing.T) {
	t.Parallel()

	dir := testutil.ShortTempDir(t)
	p := NewProvider()
	hostPort := freePort(t)

	err := p.Start(context.Background(), propnet.Config{
		LogDir: dir,
		Forwards: []propnet.PortForward{
			{Host: hostPort, Guest: 22},
		},
		EgressPolicy: &propnet.EgressPolicy{
			AllowedHosts: []propnet.EgressHost{
				{Name: "example.com"},
			},
		},
	})
	require.NoError(t, err)
	defer p.Stop()

	// The relay should exist, confirming that buildEgressRelay ran
	// (which creates implicit DNS/DHCP rules + port forward rules).
	relay := p.Relay()
	require.NotNil(t, relay, "Relay should be non-nil with EgressPolicy")

	// Verify the forwarded host port is still reachable (port forward
	// integration works alongside egress policy).
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", hostPort))
	require.NoError(t, err, "forwarded host port should be reachable with egress policy")
	_ = conn.Close()
}
