// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// whiteoutPrefix is the OCI whiteout marker prefix.
const whiteoutPrefix = ".wh."

// opaqueWhiteout is the special opaque whiteout filename.
const opaqueWhiteout = ".wh..wh..opq"

// isWhiteoutFile returns true if name has the OCI whiteout prefix.
func isWhiteoutFile(name string) bool {
	return strings.HasPrefix(filepath.Base(name), whiteoutPrefix)
}

// isOpaqueWhiteout returns true if name is the opaque whiteout marker.
func isOpaqueWhiteout(name string) bool {
	return filepath.Base(name) == opaqueWhiteout
}

// applyWhiteout removes the file or directory targeted by a whiteout entry.
// The name parameter is a relative path within the rootfs (e.g., "usr/lib/.wh.oldlib").
//
// Parent directory components are validated via SafeWalk, so a symlink
// planted as an intermediate component cannot redirect the RemoveAll onto
// the host filesystem. RemoveAll itself does not follow a symlink leaf, so
// whiteout-on-symlink (a legitimate OCI pattern) still works correctly.
func applyWhiteout(rootDir, name string) error {
	dirPart := filepath.Dir(name)
	base := filepath.Base(name)
	targetName := strings.TrimPrefix(base, whiteoutPrefix)
	relPath := filepath.Join(dirPart, targetName)

	fullPath, err := SafeWalk(rootDir, relPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// A parent directory does not exist — the whiteout target
			// cannot exist either, so this is a no-op.
			return nil
		}
		return fmt.Errorf("applying whiteout for %s: %w", name, err)
	}

	slog.Debug("applying whiteout", "target", fullPath)

	if err := os.RemoveAll(fullPath); err != nil {
		return fmt.Errorf("applying whiteout for %s: %w", name, err)
	}
	return nil
}

// applyOpaqueWhiteout removes all entries inside a directory, keeping the directory itself.
// The dirPath parameter is relative to rootDir (e.g., "usr/lib").
//
// Parent directory components are validated via SafeWalk, and the leaf is
// refused if it is a symlink — os.ReadDir follows symlinks, so a leaf
// symlink pointing outside the rootfs would otherwise enumerate and remove
// host files.
func applyOpaqueWhiteout(rootDir, dirPath string) error {
	fullDir, err := SafeWalk(rootDir, dirPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("opaque whiteout for %s: %w", dirPath, err)
	}

	info, err := os.Lstat(fullDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("stat opaque whiteout target %s: %w", dirPath, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to follow symlink for opaque whiteout: %s", dirPath)
	}
	if !info.IsDir() {
		return fmt.Errorf("opaque whiteout target is not a directory: %s", dirPath)
	}

	entries, err := os.ReadDir(fullDir)
	if err != nil {
		return fmt.Errorf("reading directory for opaque whiteout %s: %w", dirPath, err)
	}

	for _, entry := range entries {
		entryPath := filepath.Join(fullDir, entry.Name())
		slog.Debug("opaque whiteout removing entry", "path", entryPath)
		if err := os.RemoveAll(entryPath); err != nil {
			return fmt.Errorf("removing %s during opaque whiteout: %w", entryPath, err)
		}
	}
	return nil
}
