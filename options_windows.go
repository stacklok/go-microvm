// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package microvm

import (
	"os"
	"syscall"

	"github.com/stacklok/go-microvm/internal/procutil"
)

func defaultKillProcess(pid int, _ syscall.Signal) error {
	if pid < 0 {
		pid = -pid
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Kill()
}

func defaultProcessAlive(pid int) bool {
	return procutil.IsExpectedProcess(pid, "")
}

func defaultProcessIsExpected(pid int) bool {
	return procutil.IsExpectedProcess(pid, "go-microvm-runner")
}

func defaultGuestMountFSType() string {
	return "9p"
}

func defaultGuestNetworkPort() uint32 {
	return 2048
}
