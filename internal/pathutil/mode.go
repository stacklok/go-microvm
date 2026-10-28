// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import "os"

// FileMode returns the mode to give a regular file extracted or copied from
// an image: its permission bits and, when the process is not root, its
// setuid and setgid bits. On Linux hosts virtio-fs shows guests the real
// host mode, so stripping the bits breaks setuid programs such as sudo in
// the guest. A file owned by an unprivileged user grants nothing extra on
// the host; root-owned files keep the bits stripped.
func FileMode(m os.FileMode) os.FileMode {
	perm := m.Perm()
	if os.Geteuid() != 0 {
		perm |= m & (os.ModeSetuid | os.ModeSetgid)
	}
	return perm
}
