// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// lsetxattr sets name on path. Setting a user xattr needs write access to
// the file, so files and directories without the owner write bit (for
// example /etc/sudoers at 0440) are made owner-writable for the call and
// restored afterwards. Symlinks and other file types are left as they are.
func lsetxattr(path, name string, value []byte) error {
	err := unix.Lsetxattr(path, name, value, 0)
	if err == nil || (!errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM)) {
		return err
	}
	info, lerr := os.Lstat(path)
	if lerr != nil || (!info.Mode().IsRegular() && !info.IsDir()) || info.Mode().Perm()&0o200 != 0 {
		return err
	}
	mode := info.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
	if cerr := os.Chmod(path, mode|0o200); cerr != nil {
		return err
	}
	err = unix.Lsetxattr(path, name, value, 0)
	if cerr := os.Chmod(path, mode); cerr != nil && err == nil {
		err = cerr
	}
	return err
}
