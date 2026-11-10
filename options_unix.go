// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package microvm

import (
	"os"
	"syscall"

	"github.com/stacklok/go-microvm/internal/procutil"
)

// runnerBinaryName is the base name of the runner executable — used by
// the default processIsExpected check to distinguish the go-microvm
// runner from an unrelated process that happens to be at the same PID.
const runnerBinaryName = "go-microvm-runner"

func defaultKillProcess(pid int, signal syscall.Signal) error {
	return syscall.Kill(pid, signal)
}

func defaultProcessAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func defaultProcessIsExpected(pid int) bool {
	return procutil.IsExpectedProcess(pid, runnerBinaryName)
}

func defaultGuestMountFSType() string {
	return ""
}

func defaultGuestNetworkPort() uint32 {
	return 0
}
