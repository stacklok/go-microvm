// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockListener satisfies net.Listener for testing.
type mockListener struct{}

func (m *mockListener) Accept() (net.Conn, error) { return nil, nil }
func (m *mockListener) Close() error              { return nil }
func (m *mockListener) Addr() net.Addr            { return nil }

func TestCheckPortAvailable_Free(t *testing.T) {
	t.Parallel()

	pc := &portChecker{
		listen: func(_, _ string) (net.Listener, error) {
			return &mockListener{}, nil
		},
		commandCtx: exec.CommandContext,
	}

	err := pc.checkPortAvailable(context.Background(), 8080)
	assert.NoError(t, err)
}

func TestCheckPortAvailable_InUse(t *testing.T) {
	t.Parallel()

	pc := &portChecker{
		listen: func(_, _ string) (net.Listener, error) {
			return nil, fmt.Errorf("bind: address already in use")
		},
		commandCtx: func(_ context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.Command("false")
		},
	}

	err := pc.checkPortAvailable(context.Background(), 8080)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port 8080 is already in use")
}

func TestCheckPortAvailable_InUseWithProcessInfo(t *testing.T) {
	t.Parallel()

	pc := &portChecker{
		listen: func(_, _ string) (net.Listener, error) {
			return nil, fmt.Errorf("bind: address already in use")
		},
		commandCtx: func(_ context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.Command("echo",
				`LISTEN  0  128  127.0.0.1:8080  0.0.0.0:*  users:(("nginx",pid=1234,fd=6))`)
		},
	}

	err := pc.checkPortAvailable(context.Background(), 8080)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nginx (pid 1234)")
}

func TestCheckPorts_AllFree(t *testing.T) {
	t.Parallel()

	pc := &portChecker{
		listen: func(_, _ string) (net.Listener, error) {
			return &mockListener{}, nil
		},
		commandCtx: exec.CommandContext,
	}

	err := pc.checkPorts(context.Background(), []uint16{8080, 8443})
	assert.NoError(t, err)
}

func TestCheckPorts_SomeBusy(t *testing.T) {
	t.Parallel()

	pc := &portChecker{
		listen: func(_, addr string) (net.Listener, error) {
			if addr == "127.0.0.1:8080" {
				return nil, fmt.Errorf("in use")
			}
			return &mockListener{}, nil
		},
		commandCtx: func(_ context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.Command("false")
		},
	}

	err := pc.checkPorts(context.Background(), []uint16{8080, 8443})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port 8080")
}

func TestGetPortProcessInfo_SSOutput(t *testing.T) {
	t.Parallel()

	pc := &portChecker{
		commandCtx: func(_ context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.Command("echo",
				`LISTEN  0  128  127.0.0.1:8080  0.0.0.0:*  users:(("node",pid=5678,fd=12))`)
		},
	}

	info := pc.getPortProcessInfo(context.Background(), 8080)
	assert.Equal(t, "node (pid 5678)", info)
}

func TestGetPortProcessInfo_ListenNoUsers(t *testing.T) {
	t.Parallel()

	pc := &portChecker{
		commandCtx: func(_ context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.Command("echo", `LISTEN  0  128  127.0.0.1:8080  0.0.0.0:*`)
		},
	}

	info := pc.getPortProcessInfo(context.Background(), 8080)
	assert.Equal(t, "process listening", info)
}

func TestGetPortProcessInfo_NoSS(t *testing.T) {
	t.Parallel()

	pc := &portChecker{
		commandCtx: func(_ context.Context, _ string, _ ...string) *exec.Cmd {
			return exec.Command("false")
		},
	}

	info := pc.getPortProcessInfo(context.Background(), 8080)
	assert.Empty(t, info)
}

func TestPortCheck_CreatesCheck(t *testing.T) {
	t.Parallel()

	check := PortCheck(8080, 8443)
	assert.Equal(t, "ports", check.Name)
	assert.True(t, check.Required)
}
