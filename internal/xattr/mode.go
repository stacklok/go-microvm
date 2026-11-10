// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package xattr

import (
	"errors"
	"os"
	"strconv"
	"strings"
)

const overrideKey = "user.containers.override_stat"

// ErrPermissionRestore reports that the temporary owner-write permission could
// not be restored after setting an xattr.
var ErrPermissionRestore = errors.New("restore xattr target permissions")

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

// ParseOverrideStat parses a "uid:gid:0mode" override_stat payload.
func ParseOverrideStat(raw string) (int, int, int64, bool) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 3 {
		return 0, 0, 0, false
	}
	uid, uidErr := strconv.ParseUint(parts[0], 10, 32)
	gid, gidErr := strconv.ParseUint(parts[1], 10, 32)
	mode, modeErr := strconv.ParseUint(parts[2], 8, 32)
	if uidErr != nil || gidErr != nil || modeErr != nil || mode > 0o177777 {
		return 0, 0, 0, false
	}
	return int(uid), int(gid), int64(mode), true
}
