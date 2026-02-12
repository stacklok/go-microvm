// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestManager_SaveLoad_RoundTrip(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	ctx := context.Background()

	// Load and lock (creates new default state).
	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)
	defer ls.Release()

	// Modify state.
	ls.State.Name = "test-vm"
	ls.State.Image = "alpine:latest"
	ls.State.CPUs = 4
	ls.State.MemoryMB = 2048
	ls.State.Active = true
	ls.State.PID = 12345

	// Save.
	err = ls.Save()
	require.NoError(t, err)

	ls.Release()

	// Load again and verify.
	loaded, err := mgr.Load()
	require.NoError(t, err)

	assert.Equal(t, "test-vm", loaded.Name)
	assert.Equal(t, "alpine:latest", loaded.Image)
	assert.Equal(t, uint32(4), loaded.CPUs)
	assert.Equal(t, uint32(2048), loaded.MemoryMB)
	assert.True(t, loaded.Active)
	assert.Equal(t, 12345, loaded.PID)
	assert.Equal(t, stateVersion, loaded.Version)
}

func TestManager_LoadAndLock_SaveUnderLock(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	ctx := context.Background()

	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)

	ls.State.Name = "locked-vm"
	err = ls.Save()
	require.NoError(t, err)

	ls.Release()

	// Verify the state persisted.
	loaded, err := mgr.Load()
	require.NoError(t, err)
	assert.Equal(t, "locked-vm", loaded.Name)
}

func TestManager_Load_NonExistentState(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	// Load without any prior save should return a default state.
	state, err := mgr.Load()
	require.NoError(t, err)
	require.NotNil(t, state)
	assert.Equal(t, stateVersion, state.Version)
	assert.False(t, state.Active)
	assert.Empty(t, state.Name)
}

func TestManager_Exists(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	// Before saving, the state file should not exist.
	statePath := filepath.Join(dataDir, stateFileName)
	_, err := os.Stat(statePath)
	assert.True(t, os.IsNotExist(err))

	// Save some state.
	ctx := context.Background()
	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)

	ls.State.Name = "exists-test"
	err = ls.Save()
	require.NoError(t, err)
	ls.Release()

	// Now the state file should exist.
	_, err = os.Stat(statePath)
	assert.NoError(t, err)
}

func TestLockedState_Remove(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)
	ctx := context.Background()

	// Create and save state.
	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)

	ls.State.Name = "to-delete"
	err = ls.Save()
	require.NoError(t, err)

	// Verify it exists.
	statePath := filepath.Join(dataDir, stateFileName)
	_, err = os.Stat(statePath)
	require.NoError(t, err)

	// Remove while locked.
	err = ls.Remove()
	require.NoError(t, err)
	ls.Release()

	// State file should be gone.
	_, err = os.Stat(statePath)
	assert.True(t, os.IsNotExist(err))
}

func TestLockedState_AtomicSave_NoLeftoverTempFile(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)
	ctx := context.Background()

	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)

	ls.State.Name = "atomic-test"
	err = ls.Save()
	require.NoError(t, err)
	ls.Release()

	// Check that no temporary files remain in the data directory.
	entries, err := os.ReadDir(dataDir)
	require.NoError(t, err)

	for _, entry := range entries {
		name := entry.Name()
		assert.False(t, filepath.Ext(name) == ".tmp",
			"temporary file %q should not remain after atomic save", name)
	}
}

func TestLockedState_Release_Idempotent(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)
	ctx := context.Background()

	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)

	// Multiple releases should not panic.
	ls.Release()
	ls.Release()
	ls.Release()
}

func TestState_CreatedAt(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)
	ctx := context.Background()

	before := time.Now().Add(-time.Second)

	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)

	after := time.Now().Add(time.Second)

	// CreatedAt should be set automatically for new state.
	assert.True(t, ls.State.CreatedAt.After(before), "CreatedAt should be after test start")
	assert.True(t, ls.State.CreatedAt.Before(after), "CreatedAt should be before test end")

	ls.Release()
}
