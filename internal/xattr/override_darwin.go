// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package xattr

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

const overrideKey = "user.containers.override_stat"

// SetOverrideStat sets the user.containers.override_stat xattr on path
// so that libkrun's virtiofs FUSE server reports the given uid, gid,
// and mode to the guest instead of the real APFS values.
// Errors are logged at debug level and silently ignored.
func SetOverrideStat(path string, uid, gid int, mode os.FileMode) {
	unixMode := goFileModeToPosix(mode)
	val := fmt.Sprintf("%d:%d:0%o", uid, gid, unixMode)
	if err := unix.Lsetxattr(path, overrideKey, []byte(val), 0); err != nil {
		slog.Debug("setxattr override_stat failed", "path", path, "err", err)
	}
}

// SetOverrideStatFromPath sets the override_stat xattr by reading the
// file's current mode via Lstat. Useful when you know the intended
// uid/gid but the mode comes from the existing file on disk.
func SetOverrideStatFromPath(path string, uid, gid int) {
	info, err := os.Lstat(path)
	if err != nil {
		slog.Debug("lstat for override_stat failed", "path", path, "err", err)
		return
	}
	SetOverrideStat(path, uid, gid, info.Mode())
}

// CopyOverrideStat copies the user.containers.override_stat xattr from
// src to dst. No-op if src has no such xattr. Errors are silently ignored.
func CopyOverrideStat(src, dst string) {
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(src, overrideKey, buf)
	if err != nil || n == 0 {
		return
	}
	if err := unix.Lsetxattr(dst, overrideKey, buf[:n], 0); err != nil {
		slog.Debug("copy override_stat xattr failed", "dst", dst, "err", err)
	}
}

// goFileModeToPosix converts a Go os.FileMode to a POSIX st_mode value
// including file type bits.
func goFileModeToPosix(m os.FileMode) uint32 {
	mode := uint32(m.Perm())

	if m&os.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		mode |= 0o1000
	}

	switch {
	case m.IsDir():
		mode |= 0o040000 // S_IFDIR
	case m&os.ModeSymlink != 0:
		mode |= 0o120000 // S_IFLNK
	case m&os.ModeNamedPipe != 0:
		mode |= 0o010000 // S_IFIFO
	case m&os.ModeSocket != 0:
		mode |= 0o140000 // S_IFSOCK
	case m&os.ModeDevice != 0:
		if m&os.ModeCharDevice != 0 {
			mode |= 0o020000 // S_IFCHR
		} else {
			mode |= 0o060000 // S_IFBLK
		}
	default:
		mode |= 0o100000 // S_IFREG
	}

	return mode
}
