// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package rootfs

import (
	"io/fs"
	"os"
	"syscall"

	"github.com/stacklok/go-microvm/internal/pathutil"

	"golang.org/x/sys/unix"
)

// cloneFile attempts a FICLONE ioctl for COW, falling back to regular copy.
func cloneFile(src, dst string) error {
	if err := tryFiclone(src, dst); err == nil {
		return nil
	}

	// FICLONE not supported (e.g. ext4, tmpfs) — remove any partial
	// destination left by the failed ioctl before falling back.
	_ = os.Remove(dst)
	return copyFile(src, dst)
}

// tryFiclone attempts a FICLONE ioctl. Returns nil on success, error otherwise.
func tryFiclone(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = srcFile.Close() }()

	srcInfo, err := srcFile.Stat()
	if err != nil {
		return err
	}

	dstFile, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode().Perm()) //nolint:gosec // dst is inside the clone destination
	if err != nil {
		return err
	}
	defer func() { _ = dstFile.Close() }()

	if err := unix.IoctlFileClone(int(dstFile.Fd()), int(srcFile.Fd())); err != nil {
		return err
	}
	return dstFile.Chmod(pathutil.FileMode(srcInfo.Mode()))
}

// fileOwner extracts uid/gid from file info using Linux syscall.Stat_t.
func fileOwner(info fs.FileInfo) (uid, gid int) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1, -1
	}
	return int(stat.Uid), int(stat.Gid)
}
