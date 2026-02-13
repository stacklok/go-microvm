// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// IsExpectedProcess checks if the process at pid is running the expected binary.
// On Linux, reads /proc/<pid>/exe to verify the binary path. Returns false if
// the process does not exist or is running a different binary, preventing
// signals to recycled PIDs.
func IsExpectedProcess(pid int, expectedBinary string) bool {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false // Process gone or no permission
	}
	// Compare base names: the state may store just the binary name while
	// /proc/pid/exe returns the full resolved path.
	return filepath.Base(exePath) == filepath.Base(expectedBinary)
}
