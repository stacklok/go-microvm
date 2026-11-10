// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package rootfs

import "io/fs"

func cloneFile(src, dst string) error {
	return copyFile(src, dst)
}

func fileOwner(_ fs.FileInfo) (uid, gid int) {
	return -1, -1
}
