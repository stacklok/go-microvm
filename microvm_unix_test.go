// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package microvm

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestEmptyRootDir_GuestPermissions(t *testing.T) {
	oldMask := syscall.Umask(0o077)
	defer syscall.Umask(oldMask)

	dir := filepath.Join(t.TempDir(), "rootfs-work")
	require.NoError(t, emptyRootDir(dir))
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	buf := make([]byte, 256)
	n, err := unix.Getxattr(dir, "user.containers.override_stat", buf)
	if err == unix.ENOTSUP {
		t.Skip("filesystem does not support xattrs")
	}
	require.NoError(t, err)
	assert.Equal(t, "0:0:040755", string(buf[:n]))
}
