// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package pathutil

import (
	"fmt"
	"os"
	"slices"
	"syscall"
)

// RestoreSpecialBits re-applies the setuid and setgid bits of mode to the
// regular file at path after chown cleared them.
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

func inGroup(gid int) bool {
	if gid == os.Getegid() {
		return true
	}
	groups, err := os.Getgroups()
	return err == nil && slices.Contains(groups, gid)
}
