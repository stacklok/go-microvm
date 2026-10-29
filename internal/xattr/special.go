// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"os"

	"golang.org/x/sys/unix"
)

// OverrideSpecialBits returns the setuid and setgid bits of the mode that
// the override_stat xattr of path records, and whether path has a valid
// override_stat xattr.
func OverrideSpecialBits(path string) (os.FileMode, bool) {
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, overrideKey, buf)
	if err != nil || n == 0 {
		return 0, false
	}
	_, _, mode, err := parseOverride(string(buf[:n]))
	if err != nil {
		return 0, false
	}
	var bits os.FileMode
	if mode&0o4000 != 0 {
		bits |= os.ModeSetuid
	}
	if mode&0o2000 != 0 {
		bits |= os.ModeSetgid
	}
	return bits, true
}
