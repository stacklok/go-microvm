// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"os"

	"github.com/stacklok/propolis/internal/pathutil"
)

// SanitizeTarPath validates and resolves a tar entry path to prevent path
// traversal attacks. Returns the cleaned absolute path under dst.
func SanitizeTarPath(dst, entryName string) (string, error) {
	return pathutil.Contains(dst, entryName)
}

// MkdirAllNoSymlink creates directories one component at a time and refuses
// to traverse or overwrite symlinks.
func MkdirAllNoSymlink(destDir, targetDir string, mode os.FileMode) error {
	return mkdirAllNoSymlink(destDir, targetDir, mode)
}

// ValidateNoSymlinkLeaf checks that the target path is not a symlink or
// directory before writing a regular file.
func ValidateNoSymlinkLeaf(target string) error {
	return validateNoSymlinkLeaf(target)
}
