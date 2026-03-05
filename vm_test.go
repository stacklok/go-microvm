// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/net"
	"github.com/stacklok/propolis/state"
)

// mockVMHandle is a test double for hypervisor.VMHandle.
type mockVMHandle struct {
	id      string
	alive   bool
	stopErr error
	stopped bool
}

func (m *mockVMHandle) Stop(_ context.Context) error {
	m.stopped = true
	m.alive = false
	return m.stopErr
}

func (m *mockVMHandle) IsAlive() bool { return m.alive }
func (m *mockVMHandle) ID() string    { return m.id }

// mockNetProvider is a test double for net.Provider.
type mockNetProvider struct {
	startErr   error
	sockPath   string
	stopped    bool
	startCalls int
}

func (m *mockNetProvider) Start(_ context.Context, _ net.Config) error {
	m.startCalls++
	return m.startErr
}

func (m *mockNetProvider) SocketPath() string { return m.sockPath }
func (m *mockNetProvider) Stop()              { m.stopped = true }

func TestVM_Stop(t *testing.T) {
	t.Parallel()

	handle := &mockVMHandle{id: "42", alive: true}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:    "test-vm",
		handle:  handle,
		netProv: netProv,
	}

	err := vm.Stop(context.Background())
	require.NoError(t, err)
	assert.True(t, handle.stopped)
	assert.True(t, netProv.stopped)
}

func TestVM_Stop_ProcessError(t *testing.T) {
	t.Parallel()

	handle := &mockVMHandle{id: "42", alive: true, stopErr: fmt.Errorf("kill failed")}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:    "test-vm",
		handle:  handle,
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

	handle := &mockVMHandle{id: "42", alive: true}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:   "test-vm",
		handle: handle,
		ports:  []PortForward{{Host: 8080, Guest: 80}},
	}
	_ = netProv // suppress unused

	info, err := vm.Status(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "test-vm", info.Name)
	assert.True(t, info.Active)
	assert.Equal(t, 42, info.PID)
	assert.Equal(t, "42", info.ID)
	require.Len(t, info.Ports, 1)
	assert.Equal(t, uint16(8080), info.Ports[0].Host)
}

func TestVM_Status_Dead(t *testing.T) {
	t.Parallel()

	handle := &mockVMHandle{id: "42", alive: false}

	vm := &VM{
		name:    "test-vm",
		handle:  handle,
		netProv: &mockNetProvider{},
	}

	info, err := vm.Status(context.Background())
	require.NoError(t, err)
	assert.False(t, info.Active)
}

func TestVM_Remove_AlreadyStopped(t *testing.T) {
	t.Parallel()

	handle := &mockVMHandle{id: "42", alive: false}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:    "test-vm",
		handle:  handle,
		netProv: netProv,
	}

	err := vm.Remove(context.Background())
	require.NoError(t, err)
	// Stop is always called (idempotent) to avoid TOCTOU races.
	assert.True(t, handle.stopped)
	assert.True(t, netProv.stopped)
}

func TestVM_Remove_StillRunning(t *testing.T) {
	t.Parallel()

	handle := &mockVMHandle{id: "42", alive: true}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:    "test-vm",
		handle:  handle,
		netProv: netProv,
	}

	err := vm.Remove(context.Background())
	require.NoError(t, err)
	assert.True(t, handle.stopped)
	assert.True(t, netProv.stopped)
}

func TestVM_Remove_PreservesCacheContents(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	cacheDir := filepath.Join(dataDir, "cache")
	rootfsDir := filepath.Join(cacheDir, "rootfs")
	stalePath := filepath.Join(dataDir, "stale.sock")

	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootfsDir, "marker"), []byte("rootfs"), 0o644))
	require.NoError(t, os.WriteFile(stalePath, []byte("stale"), 0o644))

	vm := &VM{
		name:       "test-vm",
		handle:     &mockVMHandle{id: "42", alive: false},
		dataDir:    dataDir,
		rootfsPath: rootfsDir,
		cacheDir:   cacheDir,
		removeAll:  os.RemoveAll,
	}

	err := vm.Remove(context.Background())
	require.NoError(t, err)

	_, err = os.Stat(stalePath)
	assert.True(t, os.IsNotExist(err))

	_, err = os.Stat(rootfsDir)
	require.NoError(t, err)

	_, err = os.Stat(cacheDir)
	require.NoError(t, err)
}

func TestVM_Remove_RemovesRootfsOutsideCache(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	cacheDir := filepath.Join(dataDir, "cache")
	rootfsDir := t.TempDir()

	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(rootfsDir, "marker"), []byte("rootfs"), 0o644))

	vm := &VM{
		name:       "test-vm",
		handle:     &mockVMHandle{id: "42", alive: false},
		dataDir:    dataDir,
		rootfsPath: rootfsDir,
		cacheDir:   cacheDir,
		removeAll:  os.RemoveAll,
	}

	err := vm.Remove(context.Background())
	require.NoError(t, err)

	_, err = os.Stat(rootfsDir)
	assert.True(t, os.IsNotExist(err))

	_, err = os.Stat(cacheDir)
	require.NoError(t, err)
}

func TestVM_RunnerPID_Valid(t *testing.T) {
	t.Parallel()

	handle := &mockVMHandle{id: "1234", alive: true}
	vm := &VM{name: "test-vm", handle: handle}

	assert.Equal(t, 1234, vm.RunnerPID())
}

func TestVM_RunnerPID_NonNumericID(t *testing.T) {
	t.Parallel()

	handle := &mockVMHandle{id: "abc-123", alive: true}
	vm := &VM{name: "test-vm", handle: handle}

	assert.Equal(t, 0, vm.RunnerPID())
}

func TestVM_Accessors(t *testing.T) {
	t.Parallel()

	handle := &mockVMHandle{id: "42"}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:       "my-vm",
		handle:     handle,
		netProv:    netProv,
		dataDir:    "/data",
		rootfsPath: "/rootfs",
		ports:      []PortForward{{Host: 8080, Guest: 80}},
	}

	assert.Equal(t, "my-vm", vm.Name())
	assert.Equal(t, "42", vm.ID())
	assert.Equal(t, "/data", vm.DataDir())
	assert.Equal(t, "/rootfs", vm.RootFSPath())
	require.Len(t, vm.Ports(), 1)
	assert.Equal(t, uint16(8080), vm.Ports()[0].Host)
}

func TestVM_Stop_ClearsState(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	handle := &mockVMHandle{id: "42", alive: true}
	netProv := &mockNetProvider{}

	vm := &VM{
		name:    "test-vm",
		handle:  handle,
		netProv: netProv,
		dataDir: dataDir,
	}

	// Pre-populate state as Run() would.
	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = true
	ls.State.PID = 42
	ls.State.Image = "test:latest"
	ls.State.CPUs = 2
	ls.State.MemoryMB = 1024
	require.NoError(t, ls.Save())
	ls.Release()

	err = vm.Stop(context.Background())
	require.NoError(t, err)

	loaded, loadErr := mgr.Load()
	require.NoError(t, loadErr)
	assert.False(t, loaded.Active)
	assert.Equal(t, 0, loaded.PID)
	assert.Equal(t, "test:latest", loaded.Image)
	assert.Equal(t, uint32(2), loaded.CPUs)
	assert.Equal(t, uint32(1024), loaded.MemoryMB)
}
