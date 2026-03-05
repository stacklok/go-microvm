// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"fmt"
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
func applyWhiteout(rootDir, name string) error {
	dirPart := filepath.Dir(name)
	base := filepath.Base(name)
	targetName := strings.TrimPrefix(base, whiteoutPrefix)

	fullPath := filepath.Clean(filepath.Join(rootDir, dirPart, targetName))

	// Validate the resolved path stays within rootDir.
	if rel, err := filepath.Rel(rootDir, fullPath); err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("whiteout target escapes rootfs: %s", name)
	}

	slog.Debug("applying whiteout", "target", fullPath)

	if err := os.RemoveAll(fullPath); err != nil {
		return fmt.Errorf("applying whiteout for %s: %w", name, err)
	}
	return nil
}

// applyOpaqueWhiteout removes all entries inside a directory, keeping the directory itself.
// The dirPath parameter is relative to rootDir (e.g., "usr/lib").
func applyOpaqueWhiteout(rootDir, dirPath string) error {
	fullDir := filepath.Clean(filepath.Join(rootDir, dirPath))

	// Validate the resolved path stays within rootDir.
	if rel, err := filepath.Rel(rootDir, fullDir); err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("opaque whiteout target escapes rootfs: %s", dirPath)
	}

	entries, err := os.ReadDir(fullDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
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
