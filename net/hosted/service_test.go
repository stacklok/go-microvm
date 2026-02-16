// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hosted

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	propnet "github.com/stacklok/propolis/net"
)

func TestAddServiceBeforeStart(t *testing.T) {
	t.Parallel()

	p := NewProvider()
	p.AddService(Service{
		Port:    4483,
		Handler: http.NotFoundHandler(),
	})

	assert.Len(t, p.pendingServices, 1)
	assert.Equal(t, uint16(4483), p.pendingServices[0].Port)
}

func TestAddServiceAfterStartPanics(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := NewProvider()

	err := p.Start(context.Background(), propnet.Config{LogDir: dir})
	require.NoError(t, err)
	defer p.Stop()

	assert.Panics(t, func() {
		p.AddService(Service{
			Port:    4483,
			Handler: http.NotFoundHandler(),
		})
	})
}

func TestServiceStartCreatesRunningServices(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := NewProvider()

	p.AddService(Service{
		Port:    4483,
		Handler: http.NotFoundHandler(),
	})

	err := p.Start(context.Background(), propnet.Config{LogDir: dir})
	require.NoError(t, err)
	defer p.Stop()

	p.mu.Lock()
	count := len(p.runningServices)
	p.mu.Unlock()

	assert.Equal(t, 1, count, "one running service should exist after Start")
}

func TestMultipleServicesStart(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := NewProvider()

	p.AddService(Service{
		Port:    4483,
		Handler: http.NotFoundHandler(),
	})
	p.AddService(Service{
		Port:    4484,
		Handler: http.NotFoundHandler(),
	})

	err := p.Start(context.Background(), propnet.Config{LogDir: dir})
	require.NoError(t, err)
	defer p.Stop()

	p.mu.Lock()
	count := len(p.runningServices)
	p.mu.Unlock()

	assert.Equal(t, 2, count, "two running services should exist after Start")
}

func TestServiceListenError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := NewProvider()

	// Port 53 is used by the built-in DNS server in gvisor-tap-vsock.
	p.AddService(Service{
		Port:    53,
		Handler: http.NotFoundHandler(),
	})

	err := p.Start(context.Background(), propnet.Config{LogDir: dir})
	assert.Error(t, err, "binding to an in-use port should fail")
}

func TestServiceListenErrorCleansUp(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := NewProvider()

	// First service on a free port should succeed.
	p.AddService(Service{
		Port:    4483,
		Handler: http.NotFoundHandler(),
	})
	// Second service on port 53 (DNS) should fail.
	p.AddService(Service{
		Port:    53,
		Handler: http.NotFoundHandler(),
	})

	err := p.Start(context.Background(), propnet.Config{LogDir: dir})
	assert.Error(t, err, "should fail when a service port is unavailable")

	// The first service's listener should have been cleaned up.
	p.mu.Lock()
	count := len(p.runningServices)
	p.mu.Unlock()

	assert.Equal(t, 0, count, "running services should be cleaned up on failure")
}

func TestStopClearsRunningServices(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := NewProvider()

	p.AddService(Service{
		Port:    4485,
		Handler: http.NotFoundHandler(),
	})

	err := p.Start(context.Background(), propnet.Config{LogDir: dir})
	require.NoError(t, err)

	p.Stop()

	p.mu.Lock()
	count := len(p.runningServices)
	p.mu.Unlock()

	assert.Equal(t, 0, count, "running services should be cleared after Stop")
}

func TestNoServicesStartCleanly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := NewProvider()

	// Start with no services registered.
	err := p.Start(context.Background(), propnet.Config{LogDir: dir})
	require.NoError(t, err)
	defer p.Stop()

	p.mu.Lock()
	count := len(p.runningServices)
	p.mu.Unlock()

	assert.Equal(t, 0, count, "no running services when none registered")
}
