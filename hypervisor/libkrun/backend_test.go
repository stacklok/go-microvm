// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package libkrun

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/hypervisor"
	"github.com/stacklok/propolis/runner"
)

func TestBackend_Name(t *testing.T) {
	t.Parallel()

	b := NewBackend()
	assert.Equal(t, "libkrun", b.Name())
}

func TestBackend_PrepareRootFS_WritesKrunConfig(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	b := NewBackend()

	initCfg := hypervisor.InitConfig{
		Cmd:        []string{"/bin/sh", "-c", "echo hello"},
		Env:        []string{"PATH=/usr/bin", "FOO=bar"},
		WorkingDir: "/app",
	}

	path, err := b.PrepareRootFS(context.Background(), rootfs, initCfg)
	require.NoError(t, err)
	assert.Equal(t, rootfs, path)

	// Verify .krun_config.json was written.
	configPath := filepath.Join(rootfs, ".krun_config.json")
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "/bin/sh")
	assert.Contains(t, string(data), "FOO=bar")
	assert.Contains(t, string(data), "/app")
}

func TestBackend_PrepareRootFS_InvalidPath(t *testing.T) {
	t.Parallel()

	b := NewBackend()
	initCfg := hypervisor.InitConfig{Cmd: []string{"/bin/true"}}

	_, err := b.PrepareRootFS(context.Background(), "/nonexistent/path", initCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write krun config")
}

func TestBackend_Options(t *testing.T) {
	t.Parallel()

	b := NewBackend(
		WithRunnerPath("/custom/runner"),
		WithLibDir("/custom/lib"),
	)

	assert.Equal(t, "/custom/runner", b.runnerPath)
	assert.Equal(t, "/custom/lib", b.libDir)
}

// mockSpawner implements runner.Spawner for testing.
type mockSpawner struct {
	proc runner.ProcessHandle
	err  error
}

func (m *mockSpawner) Spawn(_ context.Context, _ runner.Config) (runner.ProcessHandle, error) {
	return m.proc, m.err
}

// mockProcessHandle implements runner.ProcessHandle for testing.
type mockProcessHandle struct {
	pid     int
	alive   bool
	stopped bool
}

func (m *mockProcessHandle) Stop(_ context.Context) error {
	m.stopped = true
	m.alive = false
	return nil
}

func (m *mockProcessHandle) IsAlive() bool { return m.alive }
func (m *mockProcessHandle) PID() int      { return m.pid }

func TestBackend_Start_Success(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42, alive: true}
	b := NewBackend(WithSpawner(&mockSpawner{proc: proc}))

	rootfs := t.TempDir()
	cfg := hypervisor.VMConfig{
		Name:       "test-vm",
		RootFSPath: rootfs,
		NumVCPUs:   2,
		RAMMiB:     512,
		DataDir:    t.TempDir(),
		PortForwards: []hypervisor.PortForward{
			{Host: 8080, Guest: 80},
		},
		FilesystemMounts: []hypervisor.FilesystemMount{
			{Tag: "workspace", HostPath: "/tmp/src"},
		},
		NetEndpoint: hypervisor.NetEndpoint{
			Type: hypervisor.NetEndpointUnixSocket,
			Path: "/tmp/net.sock",
		},
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	assert.True(t, handle.IsAlive())
	assert.Equal(t, "42", handle.ID())
}

func TestBackend_Start_SpawnError(t *testing.T) {
	t.Parallel()

	b := NewBackend(WithSpawner(&mockSpawner{
		err: assert.AnError,
	}))

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.Error(t, err)
	assert.Nil(t, handle)
	assert.Contains(t, err.Error(), "spawn runner")
}

func TestProcessHandle_Lifecycle(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 99, alive: true}
	h := &processHandle{proc: proc}

	assert.Equal(t, "99", h.ID())
	assert.True(t, h.IsAlive())

	err := h.Stop(context.Background())
	require.NoError(t, err)
	assert.False(t, h.IsAlive())
}

func TestBackend_Start_NoNetEndpoint(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 10, alive: true}
	b := NewBackend(WithSpawner(&mockSpawner{proc: proc}))

	cfg := hypervisor.VMConfig{
		RootFSPath:  t.TempDir(),
		DataDir:     t.TempDir(),
		NetEndpoint: hypervisor.NetEndpoint{Type: hypervisor.NetEndpointNone},
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "10", handle.ID())
}
