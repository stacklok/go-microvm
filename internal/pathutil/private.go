// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import (
	"fmt"
	"os"
	"strings"
)

// EnsurePrivateDir creates missing container directories with mode 0700 and,
// when KeepsSpecialBits is true, requires an effective-path private boundary.
// Existing caller directories are never chmodded. Call this on the container,
// not the image root whose permissions may subsequently be restored. Raw '..'
// components are rejected before any lexical normalization in this mode.
//
// This assumes stable, trusted ancestry: root and the effective user are trusted,
// and neither changes paths, permissions or ACLs during use. Mode bits must
// describe access (no ACL grants to other users). It is not a sandbox against
// same-user processes. Symlink targets need their own effective-path boundary;
// a private directory on the spelling of a path does not protect an escape.
func EnsurePrivateDir(path string) error {
	if err := ValidatePrivatePath(path); err != nil {
		return err
	}
	if !KeepsSpecialBits() {
		return os.MkdirAll(path, 0o700)
	}
	return ensurePrivateDir(path)
}

// ValidatePrivatePath rejects empty paths on all hosts and raw parent components
// when host special bits are retained. Call before Dir, Join or Clean: lexical
// cleaning and OS resolution of symlink/.. can select different directories.
// Relative paths also require a stable working directory during use.
func ValidatePrivatePath(path string) error {
	if path == "" || KeepsSpecialBits() {
		return validatePrivatePath(path)
	}
	return nil
}

func validatePrivatePath(path string) error {
	if path == "" {
		return fmt.Errorf("private storage path must not be empty")
	}
	for _, part := range strings.Split(path, "/") {
		if part == ".." {
			return fmt.Errorf("private storage path must not contain '..' components: %s", path)
		}
	}
	return nil
}
