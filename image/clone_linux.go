// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package image

import (
	"os"

	"golang.org/x/sys/unix"
)

// cloneFile clones the regular file src to dst, which must not exist, with
// the FICLONE ioctl: the copy shares its data blocks with src until either
// changes. It fails on file systems without reflink support (e.g. ext4,
// tmpfs) and leaves no dst behind.
func cloneFile(src, dst string) (retErr error) {
	in, err := os.Open(src) //nolint:gosec // src is a file in the layer cache
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // dst is validated by the caller
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); retErr == nil {
			retErr = cerr
		}
		if retErr != nil {
			_ = os.Remove(dst)
		}
	}()
	return unix.IoctlFileClone(int(out.Fd()), int(in.Fd()))
}

// cloneTree is not available on Linux: there is no directory clone, so
// composed rootfs snapshots are not kept.
func cloneTree(_, _ string) error { return errCloneTreeUnsupported }
