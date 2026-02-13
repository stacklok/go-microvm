// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package preflight

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckDiskSpace_Sufficient(t *testing.T) {
	t.Parallel()

	rc := &resourceChecker{
		statfs: func(_ string, buf *syscall.Statfs_t) error {
			buf.Bavail = 10 * 1024 * 1024 * 1024 / 4096 // ~10 GB with 4096 block size
			buf.Bsize = 4096
			return nil
		},
	}

	err := rc.checkDiskSpace("/tmp", 2.0)
	assert.NoError(t, err)
}

func TestCheckDiskSpace_Insufficient(t *testing.T) {
	t.Parallel()

	rc := &resourceChecker{
		statfs: func(_ string, buf *syscall.Statfs_t) error {
			buf.Bavail = 100 * 1024 * 1024 / 4096 // ~100 MB
			buf.Bsize = 4096
			return nil
		},
	}

	err := rc.checkDiskSpace("/tmp", 2.0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "insufficient disk space")
}

func TestCheckDiskSpace_StatfsError(t *testing.T) {
	t.Parallel()

	rc := &resourceChecker{
		statfs: func(_ string, _ *syscall.Statfs_t) error {
			return fmt.Errorf("statfs failed")
		},
	}

	err := rc.checkDiskSpace("/tmp", 2.0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot check disk space")
}

func TestCheckDiskSpace_EmptyDir(t *testing.T) {
	t.Parallel()

	calledWith := ""
	rc := &resourceChecker{
		statfs: func(path string, buf *syscall.Statfs_t) error {
			calledWith = path
			buf.Bavail = 10 * 1024 * 1024 * 1024 / 4096
			buf.Bsize = 4096
			return nil
		},
	}

	err := rc.checkDiskSpace("", 2.0)
	assert.NoError(t, err)
	assert.Equal(t, "/", calledWith)
}

func TestCheckResources_Sufficient(t *testing.T) {
	t.Parallel()

	rc := &resourceChecker{
		numCPU: func() int { return 8 },
		sysinfo: func(info *syscall.Sysinfo_t) error {
			info.Totalram = 16 * 1024 * 1024 * 1024 // 16 GiB
			info.Unit = 1
			return nil
		},
	}

	err := rc.checkResources(1, 1.0)
	assert.NoError(t, err)
}

func TestCheckResources_InsufficientCPU(t *testing.T) {
	t.Parallel()

	rc := &resourceChecker{
		numCPU: func() int { return 0 },
		sysinfo: func(info *syscall.Sysinfo_t) error {
			info.Totalram = 16 * 1024 * 1024 * 1024
			info.Unit = 1
			return nil
		},
	}

	err := rc.checkResources(2, 1.0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "CPU cores")
}

func TestCheckResources_InsufficientMemory(t *testing.T) {
	t.Parallel()

	rc := &resourceChecker{
		numCPU: func() int { return 8 },
		sysinfo: func(info *syscall.Sysinfo_t) error {
			info.Totalram = 256 * 1024 * 1024 // 256 MiB
			info.Unit = 1
			return nil
		},
	}

	err := rc.checkResources(1, 4.0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "total memory")
}

func TestCheckResources_SysinfoError(t *testing.T) {
	t.Parallel()

	rc := &resourceChecker{
		numCPU: func() int { return 8 },
		sysinfo: func(_ *syscall.Sysinfo_t) error {
			return fmt.Errorf("sysinfo failed")
		},
	}

	err := rc.checkResources(1, 1.0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot check system memory")
}

func TestDiskSpaceCheck_CreatesCheck(t *testing.T) {
	t.Parallel()

	check := DiskSpaceCheck("/tmp", 2.0)
	assert.Equal(t, "disk-space", check.Name)
	assert.False(t, check.Required)
}

func TestResourceCheck_CreatesCheck(t *testing.T) {
	t.Parallel()

	check := ResourceCheck(1, 1.0)
	assert.Equal(t, "resources", check.Name)
	assert.False(t, check.Required)
}
