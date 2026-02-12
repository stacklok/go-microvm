// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package runner

import (
	"os"
	"syscall"
)

// isExpectedProcess checks if the process at pid is running the expected binary.
// On macOS, /proc is not available. We fall back to verifying the process exists
// via signal 0 as a best-effort check.
func isExpectedProcess(pid int, _ string) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
