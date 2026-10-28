// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package reaper

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

var (
	// mu serialises reaping with Track, so a tracked child is registered
	// before the reaper can see it exit.
	mu      sync.Mutex
	tracked = map[int]struct{}{}
)

// Start launches a background goroutine that reaps zombie child processes
// by handling SIGCHLD signals. This is intended to run as PID 1 in a guest VM.
// Children registered with Track are left for their owner's exec.Cmd.Wait.
// The returned stop function unregisters the signal handler and stops the
// goroutine.
func Start(logger *slog.Logger) (stop func()) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGCHLD)

	go func() {
		for range ch {
			reap(logger)
		}
	}()

	return func() {
		signal.Stop(ch)
		close(ch)
	}
}

// Track runs start, which must start cmd (cmd.Start or pty.Start), and keeps
// the reaper from collecting cmd's exit status so that cmd.Wait reports it.
// Without this, the reaper's wait4 can collect a short-lived child first and
// cmd.Wait fails with ECHILD. Call the returned release after cmd.Wait
// returns.
func Track(cmd *exec.Cmd, start func() error) (release func(), err error) {
	mu.Lock()
	defer mu.Unlock()
	if err := start(); err != nil {
		return func() {}, err
	}
	pid := cmd.Process.Pid
	tracked[pid] = struct{}{}
	return func() {
		mu.Lock()
		delete(tracked, pid)
		mu.Unlock()
	}, nil
}

func reap(logger *slog.Logger) {
	mu.Lock()
	defer mu.Unlock()
	if len(tracked) == 0 {
		for {
			pid, err := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
			if errors.Is(err, syscall.ECHILD) || pid <= 0 {
				return
			}
			logger.Debug("reaped child process", "pid", pid)
		}
	}
	// wait4(-1) would also collect tracked children, so wait for each
	// untracked child by PID.
	for _, pid := range children() {
		if _, ok := tracked[pid]; ok {
			continue
		}
		if got, err := syscall.Wait4(pid, nil, syscall.WNOHANG, nil); err == nil && got == pid {
			logger.Debug("reaped child process", "pid", pid)
		}
	}
}

// children returns the PIDs of this process's children from /proc.
func children() []int {
	self := os.Getpid()
	paths, _ := filepath.Glob("/proc/[0-9]*/stat")
	var pids []int
	for _, p := range paths {
		data, err := os.ReadFile(p) //nolint:gosec // fixed /proc path pattern
		if err != nil {
			continue
		}
		if pid, ppid, ok := parseStat(data); ok && ppid == self {
			pids = append(pids, pid)
		}
	}
	return pids
}

// parseStat extracts the PID and parent PID from a /proc/<pid>/stat line:
// "pid (comm) state ppid ...". comm may contain spaces and parentheses.
func parseStat(data []byte) (pid, ppid int, ok bool) {
	open := bytes.IndexByte(data, '(')
	closing := bytes.LastIndexByte(data, ')')
	if open < 1 || closing < open {
		return 0, 0, false
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(data[:open])))
	if err != nil {
		return 0, 0, false
	}
	fields := bytes.Fields(data[closing+1:])
	if len(fields) < 2 {
		return 0, 0, false
	}
	ppid, err = strconv.Atoi(string(fields[1]))
	if err != nil {
		return 0, 0, false
	}
	return pid, ppid, true
}
