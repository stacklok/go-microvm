// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package procutil

import (
	"os"
	"syscall"
)

// IsExpectedProcess checks if the process at pid is running the expected binary.
// On macOS, /proc is not available. We fall back to verifying the process exists
// via signal 0 as a best-effort liveness check. Note: this does NOT verify the
// binary name — callers should be aware that PID recycling on macOS is not
// fully guarded against.
func IsExpectedProcess(pid int, _ string) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}
