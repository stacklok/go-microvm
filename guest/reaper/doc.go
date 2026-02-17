// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package reaper provides a SIGCHLD zombie process reaper for PID 1 init
// processes inside guest VMs. When running as PID 1, the process must reap
// child processes to prevent zombie accumulation; this package handles that
// by listening for SIGCHLD and calling wait4 in a non-blocking loop.
package reaper
