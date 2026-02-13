// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"os"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- runnerFinder tests ---

func TestFind_ExplicitPath(t *testing.T) {
	t.Parallel()

	f := runnerFinder{
		stat: func(name string) (os.FileInfo, error) {
			if name == "/explicit/runner" {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
	}

	path, err := f.find("/explicit/runner")
	require.NoError(t, err)
	assert.Equal(t, "/explicit/runner", path)
}

func TestFind_ExplicitPathNotFound(t *testing.T) {
	t.Parallel()

	f := runnerFinder{
		stat: func(_ string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	_, err := f.find("/missing/runner")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "explicit runner path not found")
}

func TestFind_SystemPATH(t *testing.T) {
	t.Parallel()

	f := runnerFinder{
		stat: func(_ string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
		lookPath: func(file string) (string, error) {
			if file == runnerBinaryName {
				return "/usr/bin/" + runnerBinaryName, nil
			}
			return "", &os.PathError{Op: "exec", Path: file, Err: os.ErrNotExist}
		},
		executable: func() (string, error) {
			return "", os.ErrNotExist
		},
	}

	path, err := f.find("")
	require.NoError(t, err)
	assert.Equal(t, "/usr/bin/"+runnerBinaryName, path)
}

func TestFind_NextToExecutable(t *testing.T) {
	t.Parallel()

	candidate := "/opt/myapp/" + runnerBinaryName

	f := runnerFinder{
		lookPath: func(_ string) (string, error) {
			return "", &os.PathError{Op: "exec", Err: os.ErrNotExist}
		},
		executable: func() (string, error) {
			return "/opt/myapp/mybin", nil
		},
		stat: func(name string) (os.FileInfo, error) {
			if name == candidate {
				return nil, nil
			}
			return nil, os.ErrNotExist
		},
	}

	path, err := f.find("")
	require.NoError(t, err)
	assert.Equal(t, candidate, path)
}

func TestFind_NotFound(t *testing.T) {
	t.Parallel()

	f := runnerFinder{
		lookPath: func(_ string) (string, error) {
			return "", &os.PathError{Op: "exec", Err: os.ErrNotExist}
		},
		executable: func() (string, error) {
			return "/opt/myapp/mybin", nil
		},
		stat: func(_ string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	_, err := f.find("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found in PATH or next to executable")
}

// --- Process tests ---

func TestProcess_Stop_AlreadyDead(t *testing.T) {
	t.Parallel()

	p := &Process{
		pid: 99999,
		deps: processDeps{
			findProcess: func(_ int) (*os.Process, error) {
				return nil, os.ErrNotExist
			},
			kill: func(_ int, _ syscall.Signal) error {
				return syscall.ESRCH
			},
		},
	}

	err := p.Stop(context.Background())
	require.NoError(t, err)
}

func TestProcess_Stop_GracefulExit(t *testing.T) {
	t.Parallel()

	terminated := false

	p := &Process{
		pid: 12345,
		deps: processDeps{
			findProcess: func(_ int) (*os.Process, error) {
				if terminated {
					return nil, os.ErrNotExist
				}
				return os.FindProcess(os.Getpid())
			},
			kill: func(_ int, sig syscall.Signal) error {
				if sig == syscall.SIGTERM {
					terminated = true
				}
				return nil
			},
		},
	}

	err := p.Stop(context.Background())
	require.NoError(t, err)
	assert.True(t, terminated, "SIGTERM should have been sent")
}

func TestProcess_IsAlive_ZeroPID(t *testing.T) {
	t.Parallel()
	p := &Process{pid: 0, deps: newProcessDeps()}
	assert.False(t, p.IsAlive())
}

func TestProcess_IsAlive_NegativePID(t *testing.T) {
	t.Parallel()
	p := &Process{pid: -1, deps: newProcessDeps()}
	assert.False(t, p.IsAlive())
}

func TestProcess_IsAlive_False(t *testing.T) {
	t.Parallel()

	p := &Process{
		pid: 99999,
		deps: processDeps{
			findProcess: func(_ int) (*os.Process, error) {
				return nil, os.ErrNotExist
			},
		},
	}
	assert.False(t, p.IsAlive())
}

func TestProcess_PID(t *testing.T) {
	t.Parallel()
	p := &Process{pid: 42, deps: newProcessDeps()}
	assert.Equal(t, 42, p.PID())
}

// --- Pure function tests ---

func TestLibPathEnvVar(t *testing.T) {
	t.Parallel()
	result := libPathEnvVar()
	if runtime.GOOS == "darwin" {
		assert.Equal(t, "DYLD_LIBRARY_PATH", result)
	} else {
		assert.Equal(t, "LD_LIBRARY_PATH", result)
	}
}

func TestIsNoSuchProcess(t *testing.T) {
	t.Parallel()
	assert.True(t, isNoSuchProcess(syscall.ESRCH))
	assert.False(t, isNoSuchProcess(syscall.EPERM))
	assert.False(t, isNoSuchProcess(os.ErrNotExist))
}

// --- Interface compliance ---

func TestDefaultSpawner_ImplementsInterface(t *testing.T) {
	t.Parallel()
	var _ Spawner = DefaultSpawner{}
}

func TestProcess_ImplementsProcessHandle(t *testing.T) {
	t.Parallel()
	var _ ProcessHandle = &Process{}
}
