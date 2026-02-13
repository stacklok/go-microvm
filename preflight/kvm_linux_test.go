// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package preflight

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockFileInfo satisfies os.FileInfo with a controllable Sys() return.
type mockFileInfo struct {
	stat *syscall.Stat_t
}

func (m mockFileInfo) Name() string       { return "kvm" }
func (m mockFileInfo) Size() int64        { return 0 }
func (m mockFileInfo) Mode() os.FileMode  { return 0o666 }
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() interface{}   { return m.stat }

func TestCheckKVM_NotExists(t *testing.T) {
	t.Parallel()

	k := &kvmChecker{
		stat: func(_ string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		},
	}

	err := k.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
	assert.Contains(t, err.Error(), "modprobe")
}

func TestCheckKVM_StatError(t *testing.T) {
	t.Parallel()

	k := &kvmChecker{
		stat: func(_ string) (os.FileInfo, error) {
			return nil, os.ErrPermission
		},
	}

	err := k.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to stat")
}

func TestCheckKVM_NotCharDevice(t *testing.T) {
	t.Parallel()

	k := &kvmChecker{
		stat: func(_ string) (os.FileInfo, error) {
			// Regular file mode, not character device.
			return mockFileInfo{stat: &syscall.Stat_t{Mode: syscall.S_IFREG | 0o666}}, nil
		},
	}

	err := k.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a character device")
}

func TestCheckKVM_PermissionDenied(t *testing.T) {
	t.Parallel()

	k := &kvmChecker{
		stat: func(_ string) (os.FileInfo, error) {
			return mockFileInfo{stat: &syscall.Stat_t{Mode: syscall.S_IFCHR | 0o666}}, nil
		},
		openFile: func(_ string, _ int, _ os.FileMode) (*os.File, error) {
			return nil, os.ErrPermission
		},
	}

	err := k.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "permission denied")
}

func TestCheckKVM_OpenError(t *testing.T) {
	t.Parallel()

	k := &kvmChecker{
		stat: func(_ string) (os.FileInfo, error) {
			return mockFileInfo{stat: &syscall.Stat_t{Mode: syscall.S_IFCHR | 0o666}}, nil
		},
		openFile: func(_ string, _ int, _ os.FileMode) (*os.File, error) {
			return nil, os.ErrClosed
		},
	}

	err := k.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot open")
}

func TestCheckKVM_Success(t *testing.T) {
	t.Parallel()

	tmpFile, err := os.CreateTemp(t.TempDir(), "kvm-mock")
	require.NoError(t, err)
	_ = tmpFile.Close()

	k := &kvmChecker{
		stat: func(_ string) (os.FileInfo, error) {
			return mockFileInfo{stat: &syscall.Stat_t{Mode: syscall.S_IFCHR | 0o666}}, nil
		},
		openFile: func(_ string, _ int, _ os.FileMode) (*os.File, error) {
			return os.Open(tmpFile.Name())
		},
	}

	err = k.check(context.Background())
	assert.NoError(t, err)
}
