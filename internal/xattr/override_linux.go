// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package xattr

import (
	"fmt"
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// SetOverrideStat sets the user.containers.override_stat xattr on path
// so that libkrun's virtiofs server reports the given uid, gid,
// and mode to the guest instead of the real host values.
// Errors are logged at debug level and silently ignored.
//
// On Linux the kernel restricts user.* xattrs to regular files and
// directories (fs/xattr.c:xattr_permission). Symlinks, named pipes,
// sockets, and device nodes are silently skipped.
func SetOverrideStat(path string, uid, gid int, mode os.FileMode) {
	// The Linux kernel refuses user.* xattrs on anything other than
	// regular files and directories. Skip early to avoid EPERM.
	if mode&(os.ModeSymlink|os.ModeNamedPipe|os.ModeSocket|os.ModeDevice) != 0 {
		return
	}

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
