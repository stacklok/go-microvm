// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package rootfs

import (
	"errors"
	"io/fs"
	"syscall"

	"golang.org/x/sys/unix"
)

// cloneFile attempts clonefile(2) for COW, falling back to regular copy.
func cloneFile(src, dst string) error {
	err := unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW)
	if err == nil {
		return nil
	}

	// Fallback for non-APFS volumes, cross-device, or destination exists.
	if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EXDEV) || errors.Is(err, unix.EEXIST) {
		return copyFile(src, dst)
	}

	return err
}

// fileOwner extracts uid/gid from file info using Darwin syscall.Stat_t.
func fileOwner(info fs.FileInfo) (uid, gid int) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(stat.Uid), int(stat.Gid)
}
