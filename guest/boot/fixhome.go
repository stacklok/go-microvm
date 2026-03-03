// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package boot

import (
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// fixHomeOwnership recursively chowns the user's home directory so that
// files injected by rootfs hooks (which may have been written by a non-root
// host user) are owned by the sandbox user. It also enforces strict SSH
// directory permissions (0700 for .ssh/, 0600 for files inside .ssh/).
//
// This runs as PID 1 (root) inside the guest, so chown always succeeds.
func fixHomeOwnership(logger *slog.Logger, home string, uid, gid int) {
	logger.Info("fixing home directory ownership", "home", home, "uid", uid, "gid", gid)

	err := filepath.WalkDir(home, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip symlinks — Lchown on a symlink itself is harmless but
		// Chmod would follow the symlink and modify the target.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}

		if chownErr := os.Lchown(path, uid, gid); chownErr != nil {
			logger.Warn("chown failed", "path", path, "error", chownErr)
		}

		// Enforce strict SSH permissions.
		// Rel cannot fail for paths from WalkDir(home, ...).
		rel, _ := filepath.Rel(home, path)
		if isSSHPath(rel) {
			enforcePerm := sshPermission(d.IsDir())
			if chmodErr := os.Chmod(path, enforcePerm); chmodErr != nil {
				logger.Warn("chmod failed", "path", path, "perm", enforcePerm, "error", chmodErr)
			}
		}

		return nil
	})
	if err != nil {
		logger.Warn("home ownership fixup incomplete", "home", home, "error", err)
	}
}

// isSSHPath returns true if the relative path is inside the .ssh directory.
func isSSHPath(rel string) bool {
	return rel == ".ssh" || strings.HasPrefix(rel, ".ssh"+string(filepath.Separator))
}

// sshPermission returns the required permission for SSH paths:
// 0700 for directories, 0600 for files.
func sshPermission(isDir bool) os.FileMode {
	if isDir {
		return 0o700
	}
	return 0o600
}
