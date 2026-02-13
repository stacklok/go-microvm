// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"fmt"
	"log/slog"
	"syscall"
	"time"

	"github.com/stacklok/propolis/state"
)

const (
	// reapGracePeriod is the time to wait after SIGTERM before sending SIGKILL.
	reapGracePeriod = 5 * time.Second
	// reapPollInterval is how often to check if the process has exited.
	reapPollInterval = 250 * time.Millisecond
)

// reapDeps holds injectable system-level operations used by the reap logic.
// Tests inject fakes; production code uses defaultReapDeps().
type reapDeps struct {
	kill              func(pid int, sig syscall.Signal) error
	isExpectedProcess func(pid int, binary string) bool
	isProcessAlive    func(pid int) bool
}

func defaultReapDeps() reapDeps {
	return reapDeps{
		kill:              func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) },
		isExpectedProcess: isExpectedProcess,
		isProcessAlive:    func(pid int) bool { return syscall.Kill(pid, 0) == nil },
	}
}

// ReapOrphanedNetProvider reads propolis state from dataDir and kills any
// orphaned network provider process left behind by a previous crash.
//
// This is safe to call at any time:
//   - No state file → no-op
//   - PID is 0 or negative → no-op (negative PIDs are cleared from state)
//   - Binary name unknown → clears state without kill (conservative)
//   - PID does not match expected binary → no-op (PID was recycled)
//   - Process already dead → clears state
//
// On success the state file is updated to clear the net provider PID.
func ReapOrphanedNetProvider(ctx context.Context, dataDir string) error {
	return reapOrphanedNetProvider(ctx, dataDir, defaultReapDeps())
}

// reapOrphanedNetProvider is the internal implementation with injectable dependencies.
func reapOrphanedNetProvider(ctx context.Context, dataDir string, deps reapDeps) error {
	stateMgr := state.NewManager(dataDir)

	ls, err := stateMgr.LoadAndLock(ctx)
	if err != nil {
		// Cannot acquire lock or read state. Log at Warn level so
		// callers have visibility into unexpected I/O failures.
		slog.Warn("reap: could not load state", "error", err)
		return nil
	}
	defer ls.Release()

	pid := ls.State.NetProviderPID
	binaryName := ls.State.NetProviderBinary

	// Guard against invalid PIDs. Negative PIDs have special semantics in
	// kill(2): -1 signals all processes, -N signals process group N. A
	// corrupted state file must never cause mass signal delivery.
	if pid <= 0 {
		if pid < 0 {
			slog.Warn("reap: invalid negative PID in state, clearing", "pid", pid)
			return clearNetProviderState(ls, deps)
		}
		return nil
	}

	slog.Info("reap: checking orphaned net provider",
		"pid", pid,
		"binary", binaryName,
	)

	// Verify the PID still belongs to the expected binary. When the binary
	// name is unknown (e.g. state written by an older version), skip the
	// kill to avoid signaling an unrelated recycled PID.
	if binaryName == "" {
		slog.Warn("reap: net provider binary name unknown, clearing state without kill",
			"pid", pid,
		)
		return clearNetProviderState(ls, deps)
	}
	if !deps.isExpectedProcess(pid, binaryName) {
		slog.Info("reap: PID no longer belongs to expected binary, clearing state",
			"pid", pid,
			"expected", binaryName,
		)
		return clearNetProviderState(ls, deps)
	}

	// Check if the process is still alive (signal 0).
	if !deps.isProcessAlive(pid) {
		slog.Info("reap: net provider process already dead, clearing state", "pid", pid)
		return clearNetProviderState(ls, deps)
	}

	// Process is alive and matches — send SIGTERM.
	slog.Info("reap: sending SIGTERM to orphaned net provider", "pid", pid)
	if err := deps.kill(pid, syscall.SIGTERM); err != nil {
		slog.Warn("reap: SIGTERM failed", "pid", pid, "error", err)
		return clearNetProviderState(ls, deps)
	}

	// Wait for the process to exit with a grace period.
	if !waitForProcessExit(pid, reapGracePeriod, deps) {
		slog.Warn("reap: net provider did not exit after SIGTERM, sending SIGKILL", "pid", pid)
		if err := deps.kill(pid, syscall.SIGKILL); err != nil {
			return fmt.Errorf("reap: SIGKILL failed for pid %d: %w", pid, err)
		}
	}

	slog.Info("reap: orphaned net provider cleaned up", "pid", pid)
	return clearNetProviderState(ls, deps)
}

// clearNetProviderState zeros out the net provider fields in persisted state.
func clearNetProviderState(ls *state.LockedState, deps reapDeps) error {
	ls.State.NetProviderPID = 0
	ls.State.NetProviderBinary = ""
	if ls.State.PID != 0 {
		// Also mark as inactive if the runner PID is set but the VM
		// is clearly not running (we're reaping orphans).
		if !deps.isProcessAlive(ls.State.PID) {
			ls.State.Active = false
			ls.State.PID = 0
		}
	}
	return ls.Save()
}

// waitForProcessExit polls until the process is gone or the timeout expires.
func waitForProcessExit(pid int, timeout time.Duration, deps reapDeps) bool {
	deadline := time.After(timeout)
	ticker := time.NewTicker(reapPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return false
		case <-ticker.C:
			if !deps.isProcessAlive(pid) {
				return true
			}
		}
	}
}
