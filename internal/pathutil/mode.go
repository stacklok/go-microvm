// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import (
	"os"
	"runtime"
)

const specialBits = os.ModeSetuid | os.ModeSetgid

// KeepsSpecialBits reports whether extracted and copied files keep their
// setuid and setgid bits. On Linux hosts virtio-fs shows guests the real
// host mode, so stripping the bits breaks setuid programs such as sudo in
// the guest. On macOS the guest sees the mode from the override_stat
// xattr instead, so the host files never need the bits. Root keeps them
// stripped because the files would be setuid root on the host.
func KeepsSpecialBits() bool {
	return runtime.GOOS == "linux" && os.Geteuid() != 0
}

// FileMode returns the mode to give a regular file extracted or copied from
// an image: its permission bits, plus its setuid and setgid bits when
// [KeepsSpecialBits] allows them.
func FileMode(m os.FileMode) os.FileMode {
	perm := m.Perm()
	if KeepsSpecialBits() {
		perm |= m & specialBits
	}
	return perm
}
