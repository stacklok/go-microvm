// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func platformProcessDeps() processDeps {
	return processDeps{
		kill:        func(pid int, signal syscall.Signal) error { return syscall.Kill(pid, signal) },
		findProcess: os.FindProcess,
	}
}

func configureRunnerCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}

// killTarget returns the negative PID for process-group-wide signals.
// Because the runner starts with Setsid, its process group ID equals its PID.
func (p *Process) killTarget() int {
	if p.pid <= 1 {
		panic(fmt.Sprintf("killTarget called with unsafe pid %d", p.pid))
	}
	return -p.pid
}

func processIsAlive(process *os.Process) bool {
	return process.Signal(syscall.Signal(0)) == nil
}

func isNoSuchProcess(err error) bool {
	return errors.Is(err, syscall.ESRCH)
}
