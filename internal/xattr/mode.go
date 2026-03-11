// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package xattr

import "os"

const overrideKey = "user.containers.override_stat"

// goFileModeToPosix converts a Go os.FileMode to a POSIX st_mode value
// including file type bits.
func goFileModeToPosix(m os.FileMode) uint32 {
	mode := uint32(m.Perm())

	if m&os.ModeSetuid != 0 {
		mode |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		mode |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		mode |= 0o1000
	}

	switch {
	case m.IsDir():
		mode |= 0o040000 // S_IFDIR
	case m&os.ModeSymlink != 0:
		mode |= 0o120000 // S_IFLNK
	case m&os.ModeNamedPipe != 0:
		mode |= 0o010000 // S_IFIFO
	case m&os.ModeSocket != 0:
		mode |= 0o140000 // S_IFSOCK
	case m&os.ModeDevice != 0:
		if m&os.ModeCharDevice != 0 {
			mode |= 0o020000 // S_IFCHR
		} else {
			mode |= 0o060000 // S_IFBLK
		}
	default:
		mode |= 0o100000 // S_IFREG
	}

	return mode
}
