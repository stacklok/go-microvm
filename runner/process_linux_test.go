// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runner

import (
	"context"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsExpectedProcess_Self(t *testing.T) {
	// Our own process should match our own executable.
	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get self executable: %v", err)
	}

	pid := os.Getpid()
	if !isExpectedProcess(pid, selfExe) {
		t.Errorf("isExpectedProcess(%d, %q) = false, want true", pid, selfExe)
	}
}

func TestIsExpectedProcess_BaseNameFallbackForRelative(t *testing.T) {
	// A relative/bare binary name still matches by base name — that is the
	// documented fallback. Absolute mismatches must no longer pass.
	pid := os.Getpid()

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get self executable: %v", err)
	}
	baseName := selfExe[len(selfExe)-len("runner.test"):] // last component
	if !isExpectedProcess(pid, baseName) {
		t.Errorf("isExpectedProcess with bare base name should match self")
	}
}

func TestIsExpectedProcess_AbsolutePathMismatchFails(t *testing.T) {
	pid := os.Getpid()

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get self executable: %v", err)
	}
	baseName := selfExe[len(selfExe)-len("runner.test"):]
	if isExpectedProcess(pid, "/some/other/path/"+baseName) {
		t.Errorf("absolute path with different dir must not match even when base name matches")
	}
}

func TestIsExpectedProcess_WrongBinary(t *testing.T) {
	// Our process should NOT match a different binary name.
	pid := os.Getpid()
	if isExpectedProcess(pid, "/usr/bin/definitely-not-this-binary") {
		t.Error("isExpectedProcess should return false for wrong binary name")
	}
}

func TestIsExpectedProcess_NonExistentPID(t *testing.T) {
	// A PID that doesn't exist should return false.
	if isExpectedProcess(99999999, "/usr/bin/anything") {
		t.Error("isExpectedProcess should return false for non-existent PID")
	}
}

func TestIsExpectedProcess_ZeroPID(t *testing.T) {
	if isExpectedProcess(0, "/usr/bin/anything") {
		t.Error("isExpectedProcess should return false for PID 0")
	}
}

func TestProcess_Stop_SkipsSignalOnPIDRecycle(t *testing.T) {
	t.Parallel()

	// Simulate PID recycling: the process at our PID is alive, but the binary
	// path doesn't match runnerPath. Stop should detect the mismatch via
	// isExpectedProcess (reads /proc/PID/exe) and skip sending any signal.
	var signalSent bool
	p := &Process{
		pid:        os.Getpid(),
		runnerPath: "/usr/bin/definitely-not-this-binary",
		deps: processDeps{
			findProcess: func(_ int) (*os.Process, error) {
				return os.FindProcess(os.Getpid())
			},
			kill: func(_ int, _ syscall.Signal) error {
				signalSent = true
				return nil
			},
		},
	}

	err := p.Stop(context.Background())
	require.NoError(t, err)
	assert.False(t, signalSent, "no signal should be sent when PID belongs to a different binary")
}

func TestProcess_IsAlive_RunnerPathMismatch(t *testing.T) {
	t.Parallel()

	// The process exists and responds to Signal(0), but the binary at the PID
	// doesn't match runnerPath. IsAlive should return false.
	p := &Process{
		pid:        os.Getpid(),
		runnerPath: "/usr/bin/definitely-not-this-binary",
		deps: processDeps{
			findProcess: func(_ int) (*os.Process, error) {
				return os.FindProcess(os.Getpid())
			},
		},
	}

	assert.False(t, p.IsAlive())
}
