// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// SetOverrideStatTree walks root and sets user.containers.override_stat
// on every file and directory. Each entry's real mode (from Lstat) is
// preserved in the xattr value. Symlinks are skipped — they cannot carry
// user.* xattrs on Linux, and skipping them prevents setting xattrs
// outside the mount boundary via symlink traversal.
//
// The root path is resolved via [filepath.EvalSymlinks] before walking,
// and every visited entry is verified to remain under the resolved root.
//
// Errors on individual entries are logged at debug level and skipped.
// Returns an error only if the root itself cannot be accessed.
//
// On platforms other than macOS and Linux a no-op stub is provided.
func SetOverrideStatTree(root string, uid, gid int) error {
	if _, err := os.Lstat(root); err != nil {
		return fmt.Errorf("access root %s: %w", root, err)
	}

	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve root: %w", err)
	}
	realRoot = filepath.Clean(realRoot)
	rootPrefix := realRoot + string(filepath.Separator)

	return filepath.WalkDir(realRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort, skip inaccessible entries
		}
		// Skip symlinks: prevents setting xattrs outside mount boundary,
		// and Linux rejects user.* xattrs on symlinks anyway.
		if d.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		// Boundary check: verify path stays under resolved root.
		cleanPath := filepath.Clean(path)
		if cleanPath != realRoot && !strings.HasPrefix(cleanPath, rootPrefix) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		SetOverrideStat(path, uid, gid, info.Mode())
		return nil
	})
}
