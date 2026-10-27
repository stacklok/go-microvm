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

// SetOverrideStat sets the user.containers.override_stat xattr on path
// so that libkrun's virtiofs FUSE server reports the given uid, gid,
// and mode to the guest instead of the real APFS values.
// Errors are logged at debug level and ignored, except failures to restore
// temporary permissions, which are returned so callers can stop publication.
func SetOverrideStat(path string, uid, gid int, mode os.FileMode) error {
	unixMode := goFileModeToPosix(mode)
	val := fmt.Sprintf("%d:%d:0%o", uid, gid, unixMode)
	if err := lsetxattr(path, overrideKey, []byte(val)); err != nil {
		slog.Debug("setxattr override_stat failed", "path", path, "err", err)
		if restoreErr := permissionRestoreError(err); restoreErr != nil {
			return restoreErr
		}
	}
	return nil
}

// SetOverrideStatFromPath sets the override_stat xattr by reading the
// file's current mode via Lstat. Useful when you know the intended
// uid/gid but the mode comes from the existing file on disk.
func SetOverrideStatFromPath(path string, uid, gid int) error {
	info, err := os.Lstat(path)
	if err != nil {
		slog.Debug("lstat for override_stat failed", "path", path, "err", err)
		return nil
	}
	return SetOverrideStat(path, uid, gid, info.Mode())
}

// CopyOverrideStat copies the user.containers.override_stat xattr from
// src to dst. No-op if src has no such xattr. Ordinary errors are logged and
// ignored; failures to restore temporary permissions are returned.
func CopyOverrideStat(src, dst string) error {
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(src, overrideKey, buf)
	if err != nil || n == 0 {
		return nil
	}
	if err := lsetxattr(dst, overrideKey, buf[:n]); err != nil {
		slog.Debug("copy override_stat xattr failed", "dst", dst, "err", err)
		if restoreErr := permissionRestoreError(err); restoreErr != nil {
			return restoreErr
		}
	}
	return nil
}
