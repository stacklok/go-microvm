// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"syscall"
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

// RestoreSpecialBits re-applies the setuid and setgid bits of mode to the
// regular file at path after chown cleared them. mode is the mode the file
// had before chown, as set from [FileMode]. A bit is restored only while
// the file belongs to the process: setuid needs the file owned by the
// effective uid, setgid additionally needs its group to be one the process
// is in. A process that can chown files to other users therefore never
// leaves set-id programs running as those users.
func RestoreSpecialBits(path string, mode os.FileMode) error {
	want := mode & specialBits
	if want == 0 {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || int(st.Uid) != os.Geteuid() {
		return nil
	}
	keep := want &^ os.ModeSetgid
	if want&os.ModeSetgid != 0 && inGroup(int(st.Gid)) {
		keep |= os.ModeSetgid
	}
	if keep&^info.Mode() == 0 {
		return nil
	}
	if err := os.Chmod(path, info.Mode().Perm()|keep); err != nil {
		return fmt.Errorf("restore setuid/setgid bits of %s: %w", path, err)
	}
	return nil
}

// inGroup reports whether gid is the effective or a supplementary group of
// the process.
func inGroup(gid int) bool {
	if gid == os.Getegid() {
		return true
	}
	groups, err := os.Getgroups()
	return err == nil && slices.Contains(groups, gid)
}
