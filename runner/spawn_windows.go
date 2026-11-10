// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package runner

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func platformProcessDeps() processDeps {
	return processDeps{
		kill: func(pid int, signal syscall.Signal) error {
			process, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("find process %d: %w", pid, err)
			}
			if signal == syscall.SIGKILL {
				return process.Kill()
			}
			return process.Signal(signal)
		},
		findProcess: os.FindProcess,
	}
}

func configureRunnerCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

func (p *Process) killTarget() int {
	if p.pid <= 0 {
		panic(fmt.Sprintf("killTarget called with unsafe pid %d", p.pid))
	}
	return p.pid
}

func processIsAlive(process *os.Process) bool {
	return isExpectedProcess(process.Pid, "")
}

func isNoSuchProcess(err error) bool {
	return errors.Is(err, os.ErrProcessDone) || errors.Is(err, windows.ERROR_INVALID_PARAMETER)
}
