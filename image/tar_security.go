// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/stacklok/go-microvm/internal/pathutil"
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

// SafeWalk resolves rel under root and verifies that no parent directory
// component along the way is a symlink. Returns the cleaned absolute path.
//
// The leaf itself is not inspected — callers that need to restrict leaf type
// (for example before ReadDir or Open) should Lstat the returned path and
// check ModeSymlink / IsDir explicitly. Callers that will call RemoveAll on
// the leaf may pass the returned path directly, since RemoveAll does not
// follow a symlink leaf.
//
// Use this before host-side operations on paths derived from untrusted tar
// metadata or similar sources. A malicious layer planting a symlink as an
// intermediate directory component would otherwise cause the subsequent
// host-side operation to redirect outside root.
func SafeWalk(root, rel string) (string, error) {
	absPath, err := SanitizeTarPath(root, rel)
	if err != nil {
		return "", err
	}
	cleanRoot := filepath.Clean(root)
	if absPath == cleanRoot {
		return absPath, nil
	}
	parent := filepath.Dir(absPath)
	relParent, err := filepath.Rel(cleanRoot, parent)
	if err != nil {
		return "", fmt.Errorf("compute relative parent: %w", err)
	}
	if relParent == "." {
		return absPath, nil
	}
	cur := cleanRoot
	for _, p := range strings.Split(relParent, string(os.PathSeparator)) {
		if p == "" || p == "." {
			continue
		}
		cur = filepath.Join(cur, p)
		info, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				return "", fmt.Errorf("missing parent directory: %s", cur)
			}
			return "", fmt.Errorf("stat %s: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing to traverse symlink: %s", cur)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("non-directory in path: %s", cur)
		}
	}
	return absPath, nil
}
