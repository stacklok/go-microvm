// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package procutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsExpectedProcess checks if the process at pid is running the expected
// binary. On Linux, reads /proc/<pid>/exe to verify the binary path. Returns
// false if the process does not exist or is running a different binary,
// preventing signals to recycled PIDs.
//
// When expectedBinary is an absolute path, the comparison is against the
// full resolved exe path — this is the strong guarantee. When
// expectedBinary is just a name, the comparison falls back to the base
// name; two unrelated binaries with the same base name on the same host
// would collide under the fallback, so callers should pass absolute paths
// when possible.
//
// The "(deleted)" suffix that the kernel appends when the underlying
// binary has been unlinked post-exec is stripped so that processes still
// running from a since-removed extract directory are correctly identified.
func IsExpectedProcess(pid int, expectedBinary string) bool {
	exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false // Process gone or no permission
	}
	exePath = strings.TrimSuffix(exePath, " (deleted)")

	if filepath.IsAbs(expectedBinary) {
		return filepath.Clean(exePath) == filepath.Clean(expectedBinary)
	}
	return filepath.Base(exePath) == filepath.Base(expectedBinary)
}
