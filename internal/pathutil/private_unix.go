// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func ensurePrivateDir(path string) error {
	if err := validatePrivatePath(path); err != nil {
		return err
	}
	if !filepath.IsAbs(path) {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("get working directory: %w", err)
		}
		path = cwd + "/" + path
	}
	hops := 0
	_, private, err := privateDir(path, true, &hops)
	if err != nil {
		return err
	}
	if !private {
		return fmt.Errorf("storage directory %q needs a private effective-path ancestor owned by UID %d (0700); if this directory is yours and does not need shared access, set its permissions to 0700; otherwise choose a private storage location", path, os.Geteuid())
	}
	return nil
}

// Resolve component by component, checking even intermediate symlink targets.
// Do not Clean first: link/.. must mean the target's parent, not the link's.
func privateDir(path string, create bool, hops *int) (string, bool, error) {
	current, private := "/", false
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			var err error
			current, private, err = privateDir(filepath.Dir(current), false, hops)
			if err != nil {
				return "", false, err
			}
			continue
		}
		next := filepath.Join(current, part)
		info, err := os.Lstat(next)
		if os.IsNotExist(err) && create {
			if err := os.Mkdir(next, 0o700); err != nil && !os.IsExist(err) {
				return "", false, fmt.Errorf("create private directory %s: %w", next, err)
			}
			info, err = os.Lstat(next)
		}
		if err != nil {
			return "", false, fmt.Errorf("stat private directory %s: %w", next, err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) {
			return "", false, fmt.Errorf("untrusted directory owner: %s", next)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			*hops++
			if *hops > 40 {
				return "", false, fmt.Errorf("too many directory symlinks: %s", next)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", false, fmt.Errorf("read directory symlink %s: %w", next, err)
			}
			if !filepath.IsAbs(target) {
				target = current + "/" + target
			}
			current, private, err = privateDir(target, false, hops)
			if err != nil {
				return "", false, err
			}
			continue
		}
		if !info.IsDir() || (!private && info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0) {
			return "", false, fmt.Errorf("not a trusted directory (type or writable by other users): %s", next)
		}
		private = private || (int(st.Uid) == os.Geteuid() && info.Mode().Perm()&0o077 == 0)
		current = next
	}
	return current, private, nil
}
