// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/state"
)

// --- Test helpers ---

// writeTestState writes a state file using the real state manager to ensure
// the serialization format matches production code.
func writeTestState(t *testing.T, dataDir string, s *state.State) {
	t.Helper()

	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	*ls.State = *s
	require.NoError(t, ls.Save())
	ls.Release()
}

// loadTestState reads back state via the real state manager.
func loadTestState(t *testing.T, dataDir string) *state.State {
	t.Helper()

	mgr := state.NewManager(dataDir)
	s, err := mgr.Load()
	require.NoError(t, err)
	return s
}

// fakeReapDeps creates reapDeps with configurable behavior.
func fakeReapDeps(alive, matchesBinary bool) reapDeps {
	return reapDeps{
		kill:              func(_ int, _ syscall.Signal) error { return nil },
		isExpectedProcess: func(_ int, _ string) bool { return matchesBinary },
		isProcessAlive:    func(_ int) bool { return alive },
	}
}

// --- No-op / early-return tests ---

func TestReapOrphanedNetProvider_NoStateFile(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	err := ReapOrphanedNetProvider(context.Background(), dataDir)
	require.NoError(t, err)
}

func TestReapOrphanedNetProvider_PIDZero(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:        1,
		Active:         false,
		NetProviderPID: 0,
	})

	err := ReapOrphanedNetProvider(context.Background(), dataDir)
	require.NoError(t, err)
}

func TestReapOrphanedNetProvider_NegativePID(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    -1,
		NetProviderBinary: "gvproxy",
	})

	deps := fakeReapDeps(true, true)
	var killCalled atomic.Bool
	deps.kill = func(_ int, _ syscall.Signal) error {
		killCalled.Store(true)
		return nil
	}

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.NoError(t, err)

	// Kill must NOT be called for negative PIDs.
	assert.False(t, killCalled.Load(), "kill should not be called for negative PID")

	// State should be cleared.
	loaded := loadTestState(t, dataDir)
	assert.Equal(t, 0, loaded.NetProviderPID)
}

func TestReapOrphanedNetProvider_EmptyBinaryName(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    12345,
		NetProviderBinary: "", // unknown binary
	})

	deps := fakeReapDeps(true, true)
	var killCalled atomic.Bool
	deps.kill = func(_ int, _ syscall.Signal) error {
		killCalled.Store(true)
		return nil
	}

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.NoError(t, err)

	// Kill must NOT be called when binary name is unknown.
	assert.False(t, killCalled.Load(), "kill should not be called when binary name is unknown")

	loaded := loadTestState(t, dataDir)
	assert.Equal(t, 0, loaded.NetProviderPID)
	assert.Empty(t, loaded.NetProviderBinary)
}

// --- PID recycled (isExpectedProcess returns false) ---

func TestReapOrphanedNetProvider_PIDRecycled(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    42,
		NetProviderBinary: "/usr/bin/gvproxy",
		PID:               100,
	})

	// Process alive but NOT the expected binary — PID was recycled.
	deps := fakeReapDeps(true, false)
	var killCalled atomic.Bool
	deps.kill = func(_ int, _ syscall.Signal) error {
		killCalled.Store(true)
		return nil
	}

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.NoError(t, err)

	assert.False(t, killCalled.Load(), "kill should not be called when PID was recycled")

	loaded := loadTestState(t, dataDir)
	assert.Equal(t, 0, loaded.NetProviderPID)
	assert.Empty(t, loaded.NetProviderBinary)
}

// --- Process already dead ---

func TestReapOrphanedNetProvider_ProcessAlreadyDead(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    42,
		NetProviderBinary: "/usr/bin/gvproxy",
		PID:               100,
	})

	// Binary matches but process is dead.
	deps := fakeReapDeps(false, true)

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.NoError(t, err)

	loaded := loadTestState(t, dataDir)
	assert.Equal(t, 0, loaded.NetProviderPID)
	// Runner PID should also be cleared since process is not alive.
	assert.Equal(t, 0, loaded.PID)
	assert.False(t, loaded.Active)
}

// --- SIGTERM path: process exits after SIGTERM ---

func TestReapOrphanedNetProvider_SIGTERMSuccess(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    42,
		NetProviderBinary: "/usr/bin/gvproxy",
	})

	var signals []syscall.Signal
	aliveCount := 2 // Process alive for 2 polls, then dies

	deps := reapDeps{
		isExpectedProcess: func(_ int, _ string) bool { return true },
		isProcessAlive: func(_ int) bool {
			if aliveCount > 0 {
				aliveCount--
				return true
			}
			return false
		},
		kill: func(_ int, sig syscall.Signal) error {
			signals = append(signals, sig)
			return nil
		},
	}

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.NoError(t, err)

	// Only SIGTERM should have been sent (no SIGKILL needed).
	assert.Equal(t, []syscall.Signal{syscall.SIGTERM}, signals)

	loaded := loadTestState(t, dataDir)
	assert.Equal(t, 0, loaded.NetProviderPID)
}

// --- SIGKILL fallback: process does not exit after SIGTERM ---

func TestReapOrphanedNetProvider_SIGKILLFallback(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    42,
		NetProviderBinary: "/usr/bin/gvproxy",
	})

	var signals []syscall.Signal

	deps := reapDeps{
		isExpectedProcess: func(_ int, _ string) bool { return true },
		isProcessAlive:    func(_ int) bool { return true }, // never dies
		kill: func(_ int, sig syscall.Signal) error {
			signals = append(signals, sig)
			return nil
		},
	}

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.NoError(t, err)

	// Should have sent SIGTERM then SIGKILL.
	require.Len(t, signals, 2)
	assert.Equal(t, syscall.SIGTERM, signals[0])
	assert.Equal(t, syscall.SIGKILL, signals[1])

	loaded := loadTestState(t, dataDir)
	assert.Equal(t, 0, loaded.NetProviderPID)
}

// --- SIGTERM fails ---

func TestReapOrphanedNetProvider_SIGTERMFails(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    42,
		NetProviderBinary: "/usr/bin/gvproxy",
	})

	deps := reapDeps{
		isExpectedProcess: func(_ int, _ string) bool { return true },
		isProcessAlive:    func(_ int) bool { return true },
		kill: func(_ int, sig syscall.Signal) error {
			if sig == syscall.SIGTERM {
				return fmt.Errorf("operation not permitted")
			}
			return nil
		},
	}

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.NoError(t, err)

	// State should still be cleared on SIGTERM failure.
	loaded := loadTestState(t, dataDir)
	assert.Equal(t, 0, loaded.NetProviderPID)
}

// --- SIGKILL fails ---

func TestReapOrphanedNetProvider_SIGKILLFails(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    42,
		NetProviderBinary: "/usr/bin/gvproxy",
	})

	deps := reapDeps{
		isExpectedProcess: func(_ int, _ string) bool { return true },
		isProcessAlive:    func(_ int) bool { return true }, // never dies
		kill: func(_ int, sig syscall.Signal) error {
			if sig == syscall.SIGKILL {
				return fmt.Errorf("operation not permitted")
			}
			return nil
		},
	}

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SIGKILL failed")
}

// --- Runner PID still alive when clearing state ---

func TestReapOrphanedNetProvider_RunnerStillAlive(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	writeTestState(t, dataDir, &state.State{
		Version:           1,
		Active:            true,
		NetProviderPID:    42,
		NetProviderBinary: "/usr/bin/gvproxy",
		PID:               100,
	})

	deps := reapDeps{
		isExpectedProcess: func(_ int, _ string) bool { return true },
		isProcessAlive: func(pid int) bool {
			// Net provider is dead (pid 42), runner is alive (pid 100).
			return pid == 100
		},
		kill: func(_ int, _ syscall.Signal) error { return nil },
	}

	err := reapOrphanedNetProvider(context.Background(), dataDir, deps)
	require.NoError(t, err)

	loaded := loadTestState(t, dataDir)
	assert.Equal(t, 0, loaded.NetProviderPID)
	// Runner is still alive, so Active and PID should be preserved.
	assert.True(t, loaded.Active)
	assert.Equal(t, 100, loaded.PID)
}

// --- LoadAndLock failure (read-only directory) ---

func TestReapOrphanedNetProvider_LoadAndLockFailure(t *testing.T) {
	t.Parallel()

	// Use a non-existent directory that can't be created.
	dataDir := "/proc/nonexistent/impossible"

	// Should return nil (fail-open), not an error.
	err := ReapOrphanedNetProvider(context.Background(), dataDir)
	require.NoError(t, err)
}

// --- Public function delegates to internal ---

func TestReapOrphanedNetProvider_PublicDelegatesToInternal(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// No state file — should be a no-op via both public and internal.
	err := ReapOrphanedNetProvider(context.Background(), dataDir)
	require.NoError(t, err)

	// Verify no state file was created.
	_, err = os.Stat(dataDir + "/propolis-state.json")
	assert.True(t, os.IsNotExist(err))
}
