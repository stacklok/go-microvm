// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package procutil

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const stillActive = 259

// IsExpectedProcess checks whether pid identifies a running process matching expectedBinary.
func IsExpectedProcess(pid int, expectedBinary string) bool {
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(handle) //nolint:errcheck // Liveness result is already determined.

	var exitCode uint32
	if err := windows.GetExitCodeProcess(handle, &exitCode); err != nil {
		return false
	}
	if exitCode != stillActive {
		return false
	}
	if expectedBinary == "" {
		return true
	}

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err != nil {
		return false
	}
	exePath := windows.UTF16ToString(buf[:size])
	if filepath.IsAbs(expectedBinary) {
		return sameWindowsExecutable(filepath.Clean(exePath), filepath.Clean(expectedBinary))
	}
	return sameWindowsExecutable(filepath.Base(exePath), filepath.Base(expectedBinary))
}

func sameWindowsExecutable(actual, expected string) bool {
	if strings.EqualFold(actual, expected) {
		return true
	}
	return strings.EqualFold(strings.TrimSuffix(actual, ".exe"), strings.TrimSuffix(expected, ".exe"))
}
