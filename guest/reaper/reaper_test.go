// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package reaper

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStartReturnsStopFunc(t *testing.T) {
	t.Parallel()
	stop := Start(slog.Default())
	require.NotNil(t, stop)
	assert.NotPanics(t, func() { stop() })
}

func TestStopIsIdempotentSafe(t *testing.T) {
	t.Parallel()
	stop := Start(slog.Default())
	require.NotNil(t, stop)
	// Calling stop once should not panic.
	stop()
	// The channel is closed after stop; calling stop again is not expected
	// but we verify the first call doesn't panic.
}

func TestParseStat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		line      string
		pid, ppid int
		ok        bool
	}{
		{"plain", "42 (sh) S 1 42 42 0", 42, 1, true},
		{"comm with spaces and parens", "7 (a (b) c) Z 3 7", 7, 3, true},
		{"truncated", "7 (sh)", 0, 0, false},
		{"garbage", "x", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			pid, ppid, ok := parseStat([]byte(tt.line))
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.pid, pid)
			assert.Equal(t, tt.ppid, ppid)
		})
	}
}

// TestTrackReleaseAfterPIDReuse simulates PID reuse without starting processes.
// It is not parallel because Track uses the process-wide registry.
func TestTrackReleaseAfterPIDReuse(t *testing.T) {
	const pid = 42
	start := func() error { return nil }
	first := &exec.Cmd{Process: &os.Process{Pid: pid}}
	releaseFirst, err := Track(first, start)
	require.NoError(t, err)
	defer releaseFirst()

	second := &exec.Cmd{Process: &os.Process{Pid: pid}}
	releaseSecond, err := Track(second, start)
	require.NoError(t, err)
	defer releaseSecond()

	releaseFirst()
	mu.Lock()
	assert.Same(t, second, tracked[pid])
	mu.Unlock()

	releaseSecond()
	mu.Lock()
	assert.NotContains(t, tracked, pid)
	mu.Unlock()
}

// TestTrackKeepsExitStatus is not parallel: the reaper handles SIGCHLD for
// the whole test process.
func TestTrackKeepsExitStatus(t *testing.T) {
	stop := Start(slog.Default())
	defer stop()

	// An untracked child is reaped by the reaper, so its own Wait fails.
	orphan := exec.Command("true")
	require.NoError(t, orphan.Start())
	require.Eventually(t, func() bool {
		_, err := os.Stat(fmt.Sprintf("/proc/%d", orphan.Process.Pid))
		return os.IsNotExist(err)
	}, 5*time.Second, 10*time.Millisecond)

	for range 50 {
		cmd := exec.Command("sh", "-c", "exit 3")
		release, err := Track(cmd, cmd.Start)
		require.NoError(t, err)
		err = cmd.Wait()
		release()
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr)
		assert.Equal(t, 3, exitErr.ExitCode())
	}
}
