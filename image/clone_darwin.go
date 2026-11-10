// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package image

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// cloneFile clones the regular file src to dst, which must not exist, with
// clonefile(2): the copy shares its data blocks with src until either
// changes. It fails on file systems without clone support (non-APFS).
func cloneFile(src, dst string) error {
	return unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW)
}

// cloneTree clones the directory tree src to dst, which must not exist, with
// a single clonefile(2) call.
func cloneTree(src, dst string) error {
	return unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW)
}

func fileOwner(info os.FileInfo) (int, int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(stat.Uid), int(stat.Gid), true
}
