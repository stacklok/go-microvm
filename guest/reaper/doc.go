// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package reaper provides a SIGCHLD zombie process reaper for PID 1 init
// processes inside guest VMs. When running as PID 1, the process must reap
// child processes to prevent zombie accumulation; this package handles that
// by listening for SIGCHLD and calling wait4 in a non-blocking loop.
// Processes that wait for their own children (for example an SSH server in
// the same process) start them with Track so the reaper leaves their exit
// status to exec.Cmd.Wait.
package reaper
