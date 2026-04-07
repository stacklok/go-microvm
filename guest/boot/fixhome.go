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
	"syscall"
)

// fixHomeOwnership ensures the user's home directory and critical
// subdirectories (.ssh/) have correct ownership and permissions.
//
// When the home directory is already owned by uid:gid (the common case
// on Linux with user-namespace-backed virtiofs), only the .ssh/
// subtree is walked to enforce strict SSH permissions. This avoids a
// costly recursive chown of the entire home directory which can contain
// hundreds of thousands of files from the OCI image.
//
// A full recursive chown is only performed when the home directory
// itself has wrong ownership (e.g. macOS hosts without user namespaces
// where rootfs hooks cannot chown to the sandbox UID).
//
// This runs as PID 1 (root) inside the guest, so chown always succeeds.
func fixHomeOwnership(logger *slog.Logger, home string, uid, gid int) {
	logger.Info("fixing home directory ownership", "home", home, "uid", uid, "gid", gid)

	if homeAlreadyOwned(home, uid, gid) {
		logger.Info("home directory already owned correctly, fixing .ssh only")
		fixSSHPermissions(logger, home, uid, gid)
		return
	}

	logger.Info("home directory has wrong ownership, running full recursive chown")
	fullRecursiveChown(logger, home, uid, gid)
}

// homeAlreadyOwned checks whether the home directory itself is owned by
// the expected uid and gid.
func homeAlreadyOwned(home string, uid, gid int) bool {
	info, err := os.Lstat(home)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(stat.Uid) == uid && int(stat.Gid) == gid
}

// fixSSHPermissions walks only the .ssh/ subtree under home, chowning
// and enforcing strict permissions (0700 dirs, 0600 files).
func fixSSHPermissions(logger *slog.Logger, home string, uid, gid int) {
	sshDir := filepath.Join(home, ".ssh")
	if _, err := os.Stat(sshDir); os.IsNotExist(err) {
		return
	}

	err := filepath.WalkDir(sshDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if chownErr := os.Lchown(path, uid, gid); chownErr != nil {
			logger.Warn("chown failed", "path", path, "error", chownErr)
		}
		perm := sshPermission(d.IsDir())
		if chmodErr := os.Chmod(path, perm); chmodErr != nil {
			logger.Warn("chmod failed", "path", path, "perm", perm, "error", chmodErr)
		}
		return nil
	})
	if err != nil {
		logger.Warn(".ssh permission fixup incomplete", "error", err)
	}
}

// fullRecursiveChown walks the entire home tree, chowning every entry
// and enforcing SSH permissions on .ssh/ paths.
func fullRecursiveChown(logger *slog.Logger, home string, uid, gid int) {
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
