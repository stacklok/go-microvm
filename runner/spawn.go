// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

// Compile-time interface assertions.
var (
	_ Spawner       = DefaultSpawner{}
	_ ProcessHandle = (*Process)(nil)
)

const (
	// runnerBinaryName is the name of the propolis-runner binary.
	runnerBinaryName = "propolis-runner"
	// stopTimeout is the maximum time to wait for the process to exit after SIGTERM.
	stopTimeout = 30 * time.Second
	// stopPollInterval is the interval between process liveness checks during stop.
	stopPollInterval = 250 * time.Millisecond
)

// processDeps holds injectable system-level operations used by Process.
// Tests inject fakes; production code uses the defaults from newProcessDeps().
type processDeps struct {
	kill        func(pid int, sig syscall.Signal) error
	findProcess func(pid int) (*os.Process, error)
}

func newProcessDeps() processDeps {
	return processDeps{
		kill:        func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) },
		findProcess: os.FindProcess,
	}
}

// runnerFinder locates the propolis-runner binary with injectable lookups.
type runnerFinder struct {
	stat       func(string) (os.FileInfo, error)
	lookPath   func(string) (string, error)
	executable func() (string, error)
}

func newRunnerFinder() runnerFinder {
	return runnerFinder{
		stat:       os.Stat,
		lookPath:   exec.LookPath,
		executable: os.Executable,
	}
}

// Process represents a running VM runner subprocess.
type Process struct {
	// pid is the process ID of the runner subprocess.
	pid int
	// runnerPath is the resolved path to the runner binary, used to verify
	// process identity before sending signals (prevents signaling recycled PIDs).
	runnerPath string
	cmd        *exec.Cmd
	deps       processDeps
}

// PID returns the process ID (implements ProcessHandle).
func (p *Process) PID() int { return p.pid }

// killTarget returns the negative PID for process-group-wide signals.
// Because the runner starts with Setsid: true, its PGID == PID,
// so kill(-pid, sig) targets the entire process group.
// Panics if pid <= 1 to prevent kill(0) (own group) or kill(-1) (all processes).
func (p *Process) killTarget() int {
	if p.pid <= 1 {
		panic(fmt.Sprintf("killTarget called with unsafe pid %d", p.pid))
	}
	return -p.pid
}

// Spawn starts the propolis-runner binary as a detached subprocess.
// Deprecated: Use SpawnProcess or DefaultSpawner instead.
func Spawn(ctx context.Context, cfg Config) (*Process, error) {
	return SpawnProcess(ctx, cfg)
}

// SpawnProcess starts the propolis-runner binary as a detached subprocess.
// The runner binary receives the VM configuration as a JSON string in argv[1].
// On success, the returned Process can be used to monitor and stop the VM.
func SpawnProcess(ctx context.Context, cfg Config) (*Process, error) {
	finder := newRunnerFinder()
	runnerPath, err := finder.find(cfg.RunnerPath)
	if err != nil {
		return nil, fmt.Errorf("runner binary not found: %w", err)
	}

	configJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("marshal runner config: %w", err)
	}

	// Use exec.Command (NOT exec.CommandContext) because the runner is a
	// long-lived process that should outlive the calling context. The context
	// may have a timeout that we do not want to propagate to the VM process.
	// The runner lifecycle is managed explicitly via Stop().
	_ = ctx // acknowledged but intentionally unused for exec.Command
	cmd := exec.Command(runnerPath, string(configJSON))
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Create new session (detach from terminal)
	}

	// Set library search path for bundled libraries if available.
	if cfg.LibDir != "" {
		cmd.Env = append(os.Environ(), libPathEnvVar()+"="+cfg.LibDir)
	}

	// Redirect stdout/stderr to log file if configured.
	if cfg.VMLogPath != "" {
		logFile, err := os.OpenFile(cfg.VMLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, fmt.Errorf("open vm log file: %w", err)
		}
		cmd.Stdout = logFile
		cmd.Stderr = logFile
		// Close after Start — the child process inherits the file descriptors.
		defer func() { _ = logFile.Close() }()
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start runner process: %w", err)
	}

	proc := &Process{
		pid:        cmd.Process.Pid,
		runnerPath: runnerPath,
		cmd:        cmd,
		deps:       newProcessDeps(),
	}

	// Start a goroutine to reap the child process when it exits. This prevents
	// zombie processes. The goroutine terminates when cmd.Wait returns.
	go func() {
		waitErr := cmd.Wait()
		if waitErr != nil {
			slog.Warn("runner process exited with error",
				"pid", cmd.Process.Pid,
				"error", waitErr,
			)
		} else {
			slog.Info("runner process exited normally",
				"pid", cmd.Process.Pid,
			)
		}
	}()

	return proc, nil
}

// Stop sends SIGTERM to the runner process and waits for it to exit.
// If the process does not exit within 30 seconds, it sends SIGKILL.
func (p *Process) Stop(ctx context.Context) error {
	if !p.IsAlive() {
		return nil
	}

	// Verify process identity before signaling to avoid killing a recycled PID
	// that now belongs to an unrelated process.
	if p.runnerPath != "" && !isExpectedProcess(p.pid, p.runnerPath) {
		slog.Warn("PID no longer belongs to the expected runner binary, skipping signal",
			"pid", p.pid,
			"expected_binary", p.runnerPath,
		)
		return nil
	}

	// Send SIGTERM for graceful shutdown.
	// Use killTarget() (negative PID) to signal the entire process group,
	// ensuring any children spawned by the runner are also terminated.
	if err := p.deps.kill(p.killTarget(), syscall.SIGTERM); err != nil {
		// If the process is already gone, that is fine.
		if !isNoSuchProcess(err) {
			return fmt.Errorf("send SIGTERM to pid %d: %w", p.pid, err)
		}
		return nil
	}

	// Poll until the process exits or the timeout expires.
	deadline := time.Now().Add(stopTimeout)
	ticker := time.NewTicker(stopPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Context canceled — force kill.
			_ = p.deps.kill(p.killTarget(), syscall.SIGKILL)
			return ctx.Err()
		case <-ticker.C:
			if !p.IsAlive() {
				return nil
			}
			if time.Now().After(deadline) {
				// Timeout — force kill.
				if err := p.deps.kill(p.killTarget(), syscall.SIGKILL); err != nil && !isNoSuchProcess(err) {
					return fmt.Errorf("send SIGKILL to pid %d: %w", p.pid, err)
				}
				return nil
			}
		}
	}
}

// IsAlive checks if the process is still running.
// When a runner path is known, it also verifies the PID still belongs to the
// expected binary (prevents false positives from PID reuse).
func (p *Process) IsAlive() bool {
	if p.pid <= 0 {
		return false
	}
	process, err := p.deps.findProcess(p.pid)
	if err != nil {
		return false
	}
	if process.Signal(syscall.Signal(0)) != nil {
		return false
	}
	// If we know the runner path, verify the PID still belongs to it.
	if p.runnerPath != "" {
		return isExpectedProcess(p.pid, p.runnerPath)
	}
	return true
}

// find locates the propolis-runner binary. It checks, in order:
// 1. The explicit path provided in cfg.RunnerPath
// 2. The system PATH
// 3. Next to the current executable
func (f *runnerFinder) find(explicit string) (string, error) {
	// 1. Explicit path.
	if explicit != "" {
		if _, err := f.stat(explicit); err == nil {
			return explicit, nil
		}
		return "", fmt.Errorf("explicit runner path not found: %s", explicit)
	}

	// 2. System PATH.
	if p, err := f.lookPath(runnerBinaryName); err == nil {
		return p, nil
	}

	// 3. Next to the current executable.
	execPath, err := f.executable()
	if err == nil {
		candidate := filepath.Join(filepath.Dir(execPath), runnerBinaryName)
		if _, err := f.stat(candidate); err == nil {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("%s not found in PATH or next to executable", runnerBinaryName)
}

// libPathEnvVar returns the platform-specific environment variable for the
// shared library search path.
func libPathEnvVar() string {
	if runtime.GOOS == "darwin" {
		return "DYLD_LIBRARY_PATH"
	}
	return "LD_LIBRARY_PATH"
}

// isNoSuchProcess returns true if the error indicates the process does not exist.
func isNoSuchProcess(err error) bool {
	return errors.Is(err, syscall.ESRCH)
}
