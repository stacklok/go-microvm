// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
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

func TestManager_LoadAndLockWithRetry_ImmediateSuccess(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	ctx := context.Background()

	ls, err := mgr.LoadAndLockWithRetry(ctx, 5*time.Second)
	require.NoError(t, err)
	defer ls.Release()

	assert.NotNil(t, ls.State)
	assert.Equal(t, stateVersion, ls.State.Version)
}

func TestManager_LoadAndLockWithRetry_WaitsForLock(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	ctx := context.Background()

	// Acquire the lock externally using flock to simulate contention.
	lockPath := filepath.Join(dataDir, lockFileName)
	require.NoError(t, os.MkdirAll(dataDir, 0o700))
	fl := flock.New(lockPath)
	locked, err := fl.TryLock()
	require.NoError(t, err)
	require.True(t, locked)

	// Release the external lock after a short delay so the retry succeeds.
	go func() {
		time.Sleep(600 * time.Millisecond)
		_ = fl.Unlock()
	}()

	ls, err := mgr.LoadAndLockWithRetry(ctx, 5*time.Second)
	require.NoError(t, err)
	defer ls.Release()

	assert.NotNil(t, ls.State)
}

func TestManager_LoadAndLockWithRetry_Timeout(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	ctx := context.Background()

	// Hold the lock for the entire duration so the retry always fails.
	lockPath := filepath.Join(dataDir, lockFileName)
	require.NoError(t, os.MkdirAll(dataDir, 0o700))
	fl := flock.New(lockPath)
	locked, err := fl.TryLock()
	require.NoError(t, err)
	require.True(t, locked)
	defer fl.Unlock()

	_, err = mgr.LoadAndLockWithRetry(ctx, 500*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestManager_Load_CorruptJSON(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	// Write garbage bytes to the state file.
	statePath := filepath.Join(dataDir, stateFileName)
	require.NoError(t, os.WriteFile(statePath, []byte("{corrupt!!!"), 0o600))

	_, err := mgr.Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse state file")
}

func TestManager_LoadAndLock_CorruptJSON_ReleasesLock(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	ctx := context.Background()

	// Write corrupt JSON to the state file.
	statePath := filepath.Join(dataDir, stateFileName)
	require.NoError(t, os.MkdirAll(dataDir, 0o700))
	require.NoError(t, os.WriteFile(statePath, []byte("not-json"), 0o600))

	// LoadAndLock should fail due to corrupt JSON.
	_, err := mgr.LoadAndLock(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse state file")

	// Fix the state file so a subsequent load succeeds.
	validState, err := json.Marshal(&State{Version: 1, Name: "recovered"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(statePath, validState, 0o600))

	// The lock should have been released, so we can acquire it again.
	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)
	defer ls.Release()

	assert.Equal(t, "recovered", ls.State.Name)
}

func TestLockedState_Save_SetsVersion(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	ctx := context.Background()

	ls, err := mgr.LoadAndLock(ctx)
	require.NoError(t, err)
	defer ls.Release()

	// Zero out the version to verify Save sets it.
	ls.State.Version = 0
	ls.State.Name = "version-test"

	err = ls.Save()
	require.NoError(t, err)

	// Read back and verify version is set to stateVersion.
	loaded, err := mgr.Load()
	require.NoError(t, err)
	assert.Equal(t, stateVersion, loaded.Version)
	assert.Equal(t, "version-test", loaded.Name)
}

func TestManager_ConcurrentLoadAndLock(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	mgr := NewManager(dataDir)

	const goroutines = 10
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			ls, err := mgr.LoadAndLockWithRetry(ctx, 30*time.Second)
			if err != nil {
				errs <- fmt.Errorf("goroutine %d lock: %w", idx, err)
				return
			}

			// Modify and save state under lock.
			ls.State.Name = fmt.Sprintf("vm-%d", idx)
			ls.State.CPUs = uint32(idx + 1)
			ls.State.Active = true

			if err := ls.Save(); err != nil {
				ls.Release()
				errs <- fmt.Errorf("goroutine %d save: %w", idx, err)
				return
			}

			ls.Release()
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	// Final state should be valid JSON written by one of the goroutines.
	loaded, err := mgr.Load()
	require.NoError(t, err)
	assert.True(t, loaded.Active)
	assert.Equal(t, stateVersion, loaded.Version)
	assert.NotEmpty(t, loaded.Name)
}
