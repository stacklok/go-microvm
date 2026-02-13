// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/net"
	"github.com/stacklok/propolis/state"
)

// mockProcessHandle is a test double for runner.ProcessHandle.
type mockProcessHandle struct {
	pid     int
	alive   bool
	stopErr error
	stopped bool
}

func (m *mockProcessHandle) Stop(_ context.Context) error {
	m.stopped = true
	m.alive = false
	return m.stopErr
}

func (m *mockProcessHandle) IsAlive() bool { return m.alive }
func (m *mockProcessHandle) PID() int      { return m.pid }

// mockNetProvider is a test double for net.Provider.
type mockNetProvider struct {
	startErr   error
	sockPath   string
	pid        int
	stopped    bool
	startCalls int
	binaryPath string
}

func (m *mockNetProvider) Start(_ context.Context, _ net.Config) error {
	m.startCalls++
	return m.startErr
}

func (m *mockNetProvider) SocketPath() string { return m.sockPath }
func (m *mockNetProvider) PID() int           { return m.pid }
func (m *mockNetProvider) BinaryPath() string {
	if m.binaryPath == "" {
		return "/mock/gvproxy"
	}
	return m.binaryPath
}
func (m *mockNetProvider) Stop() { m.stopped = true }

func TestVM_Stop(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42, alive: true}
	netProv := &mockNetProvider{pid: 100}

	vm := &VM{
		name:    "test-vm",
		proc:    proc,
		netProv: netProv,
	}

	err := vm.Stop(context.Background())
	require.NoError(t, err)
	assert.True(t, proc.stopped)
	assert.True(t, netProv.stopped)
}

func TestVM_Stop_ProcessError(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42, alive: true, stopErr: fmt.Errorf("kill failed")}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:    "test-vm",
		proc:    proc,
		netProv: netProv,
	}

	err := vm.Stop(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stop vm process")
	// Net provider should NOT be stopped if process stop fails.
	assert.False(t, netProv.stopped)
}

func TestVM_Status_Alive(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42, alive: true}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:  "test-vm",
		proc:  proc,
		ports: []PortForward{{Host: 8080, Guest: 80}},
	}
	_ = netProv // suppress unused

	info, err := vm.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-vm", info.Name)
	assert.True(t, info.Active)
	assert.Equal(t, 42, info.PID)
	require.Len(t, info.Ports, 1)
	assert.Equal(t, uint16(8080), info.Ports[0].Host)
}

func TestVM_Status_Dead(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42, alive: false}

	vm := &VM{
		name:    "test-vm",
		proc:    proc,
		netProv: &mockNetProvider{},
	}

	info, err := vm.Status(context.Background())
	require.NoError(t, err)
	assert.False(t, info.Active)
}

func TestVM_Remove_AlreadyStopped(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42, alive: false}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:    "test-vm",
		proc:    proc,
		netProv: netProv,
	}

	err := vm.Remove(context.Background())
	require.NoError(t, err)
	// Should not have called Stop since process is already dead.
	assert.False(t, proc.stopped)
	assert.False(t, netProv.stopped)
}

func TestVM_Remove_StillRunning(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42, alive: true}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:    "test-vm",
		proc:    proc,
		netProv: netProv,
	}

	err := vm.Remove(context.Background())
	require.NoError(t, err)
	assert.True(t, proc.stopped)
	assert.True(t, netProv.stopped)
}

func TestVM_Accessors(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42}
	netProv := &mockNetProvider{pid: 100}

	vm := &VM{
		name:       "my-vm",
		proc:       proc,
		netProv:    netProv,
		dataDir:    "/data",
		rootfsPath: "/rootfs",
		ports:      []PortForward{{Host: 8080, Guest: 80}},
	}

	assert.Equal(t, "my-vm", vm.Name())
	assert.Equal(t, 42, vm.PID())
	assert.Equal(t, "/data", vm.DataDir())
	assert.Equal(t, "/rootfs", vm.RootFSPath())
	assert.Equal(t, 100, vm.NetProviderPID())
	require.Len(t, vm.Ports(), 1)
	assert.Equal(t, uint16(8080), vm.Ports()[0].Host)
}

func TestVM_Stop_ClearsState(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	proc := &mockProcessHandle{pid: 42, alive: true}
	netProv := &mockNetProvider{pid: 100}

	vm := &VM{
		name:    "test-vm",
		proc:    proc,
		netProv: netProv,
		dataDir: dataDir,
	}

	// Pre-populate state as Run() would.
	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = true
	ls.State.PID = 42
	ls.State.NetProviderPID = 100
	ls.State.NetProviderBinary = "/usr/bin/gvproxy"
	require.NoError(t, ls.Save())
	ls.Release()

	err = vm.Stop(context.Background())
	require.NoError(t, err)

	loaded, loadErr := mgr.Load()
	require.NoError(t, loadErr)
	assert.False(t, loaded.Active)
	assert.Equal(t, 0, loaded.PID)
	assert.Equal(t, 0, loaded.NetProviderPID)
	assert.Empty(t, loaded.NetProviderBinary)
}
