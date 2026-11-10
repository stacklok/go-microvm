// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package vhd

import (
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const overrideStatKey = "user.containers.override_stat"

func getOverrideStat(path string) (int, int, int64, bool) {
	buffer := make([]byte, 256)
	bytesRead, err := unix.Lgetxattr(path, overrideStatKey, buffer)
	if err != nil || bytesRead == 0 {
		return 0, 0, 0, false
	}
	parts := strings.Split(string(buffer[:bytesRead]), ":")
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
