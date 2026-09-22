// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package virtiofs

import (
	"context"
	"fmt"

	"github.com/stacklok/go-microvm/internal/xattr"
)

// PrepareOwnership sets libkrun's override_stat ownership metadata on an
// authorized host entry or tree. relativePath must be "." for the whole root,
// or a non-empty relative path naming one entry and, if it is a directory, its
// subtree.
//
// The operation is strict: the first inaccessible entry, malformed xattr,
// unsupported file type, or xattr failure is returned. The caller needs host
// permission to read existing xattrs and write new or changed metadata; an
// unannotated 0400 file commonly rejects a write by an unprivileged owner. A
// matching xattr is not rewritten. A new xattr derives its guest mode from the
// host inode; an existing xattr preserves its guest permission, set-ID, and
// sticky bits.
//
// The final component of root and every component of relativePath are opened
// without following symlinks. Symlinks below the target are skipped. Traversal
// after root acquisition is descriptor-relative. The caller must trust and
// protect root's parent during acquisition; hard links in root authorize their
// inode even when it also has names outside root.
//
// Host ownership and mode are never changed. Preparation is non-transactional:
// an error may leave earlier entries prepared. Callers must synchronize rename,
// creation, replacement, and guest chmod operations. This function provides no
// cache invalidation or atomic visibility to a running guest.
func PrepareOwnership(ctx context.Context, root, relativePath string, uid, gid uint32) error {
	_, err := xattr.PrepareOwnership(ctx, root, relativePath, uid, gid, true)
	if err != nil {
		return fmt.Errorf("strict ownership preparation: %w", err)
	}
	return nil
}
