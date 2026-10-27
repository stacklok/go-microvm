// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

type writableOps struct {
	open      func(string, int, uint32) (int, error)
	fstat     func(int, *unix.Stat_t) error
	fchmod    func(int, uint32) error
	fsetxattr func(int, string, []byte, int) error
	close     func(int) error
}

var defaultWritableOps = writableOps{
	open:      unix.Open,
	fstat:     unix.Fstat,
	fchmod:    unix.Fchmod,
	fsetxattr: unix.Fsetxattr,
	close:     unix.Close,
}

// lsetxattr sets name on path. If the initial path-based operation is denied,
// it pins the leaf without following symlinks, temporarily adds owner-write on
// that inode, and restores its original POSIX permission and special bits.
// Parent directories are trusted private preparation directories; this pins
// only the leaf, not the full path.
// The fallback requires read access to open the target. Callers preparing image
// trees ensure owner-read on files and owner access on directories. If the open
// is denied (for example, an unreadable 0111 or 0000 entry), no permissions are
// changed and ordinary best-effort callers skip the override. Do not chmod by
// pathname to obtain read access: that would reintroduce the replacement race.
func lsetxattr(path, name string, value []byte) error {
	return lsetxattrWith(path, name, value, unix.Lsetxattr, defaultWritableOps)
}

func permissionRestoreError(err error) error {
	if errors.Is(err, ErrPermissionRestore) {
		return err
	}
	return nil
}

func lsetxattrWith(path, name string, value []byte, lset func(string, string, []byte, int) error, ops writableOps) (retErr error) {
	initialErr := lset(path, name, value, 0)
	if initialErr == nil || (!errors.Is(initialErr, unix.EACCES) && !errors.Is(initialErr, unix.EPERM)) {
		return initialErr
	}

	fd, openErr := ops.open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if openErr != nil {
		return fmt.Errorf("open xattr target without following symlinks: %w", openErr)
	}
	defer func() { _ = ops.close(fd) }()

	var stat unix.Stat_t
	if statErr := ops.fstat(fd, &stat); statErr != nil {
		return fmt.Errorf("stat xattr target: %w", statErr)
	}
	typeBits := uint32(stat.Mode) & unix.S_IFMT
	if (typeBits != unix.S_IFREG && typeBits != unix.S_IFDIR) || stat.Mode&0o200 != 0 {
		return initialErr
	}
	mode := uint32(stat.Mode) & 0o7777
	if chmodErr := ops.fchmod(fd, mode|0o200); chmodErr != nil {
		return fmt.Errorf("make xattr target owner-writable: %w", chmodErr)
	}

	defer func() {
		if restoreErr := ops.fchmod(fd, mode); restoreErr != nil {
			restoreErr = fmt.Errorf("%w: %w", ErrPermissionRestore, restoreErr)
			retErr = errors.Join(retErr, restoreErr)
		}
	}()
	return ops.fsetxattr(fd, name, value, 0)
}
