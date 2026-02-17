// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"encoding/binary"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

// ptyRequest is the payload of an SSH "pty-req" request.
type ptyRequest struct {
	Term   string
	Width  uint32
	Height uint32
	PxW    uint32
	PxH    uint32
	Modes  string
}

// windowChangeRequest is the payload of an SSH "window-change" request.
type windowChangeRequest struct {
	Width  uint32
	Height uint32
	PxW    uint32
	PxH    uint32
}

// signalRequest is the payload of an SSH "signal" request.
type signalRequest struct {
	Signal string
}

// sshSignalToOS maps SSH signal names to OS signal values.
var sshSignalToOS = map[string]syscall.Signal{
	"ABRT": syscall.SIGABRT,
	"ALRM": syscall.SIGALRM,
	"FPE":  syscall.SIGFPE,
	"HUP":  syscall.SIGHUP,
	"ILL":  syscall.SIGILL,
	"INT":  syscall.SIGINT,
	"KILL": syscall.SIGKILL,
	"PIPE": syscall.SIGPIPE,
	"QUIT": syscall.SIGQUIT,
	"SEGV": syscall.SIGSEGV,
	"TERM": syscall.SIGTERM,
	"USR1": syscall.SIGUSR1,
	"USR2": syscall.SIGUSR2,
}

// allowedEnvVars is the set of environment variable names that clients
// may inject via the "env" channel request.
var allowedEnvVars = map[string]bool{
	"TERM":      true,
	"LANG":      true,
	"LC_ALL":    true,
	"LC_CTYPE":  true,
	"COLORTERM": true,
	"EDITOR":    true,
	"VISUAL":    true,
}

// sessionState tracks per-session mutable state accumulated across
// channel requests.
type sessionState struct {
	ptyReq *ptyRequest
	env    map[string]string
}

// handleSession processes SSH session requests on the given channel.
func (s *Server) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()

	state := &sessionState{
		env: make(map[string]string),
	}

	for req := range requests {
		switch req.Type {
		case "pty-req":
			var pr ptyRequest
			if err := ssh.Unmarshal(req.Payload, &pr); err != nil {
				s.logger.Warn("malformed pty-req", "error", err)
				replyRequest(req, false)
				continue
			}
			state.ptyReq = &pr
			state.env["TERM"] = pr.Term
			replyRequest(req, true)

		case "env":
			var kv struct {
				Name  string
				Value string
			}
			if err := ssh.Unmarshal(req.Payload, &kv); err != nil {
				s.logger.Warn("malformed env request", "error", err)
				replyRequest(req, false)
				continue
			}
			if allowedEnvVars[kv.Name] {
				state.env[kv.Name] = kv.Value
				replyRequest(req, true)
			} else {
				s.logger.Debug("rejected env var", "name", kv.Name)
				replyRequest(req, false)
			}

		case "exec":
			var payload struct {
				Command string
			}
			if err := ssh.Unmarshal(req.Payload, &payload); err != nil {
				s.logger.Warn("malformed exec request", "error", err)
				replyRequest(req, false)
				continue
			}
			replyRequest(req, true)
			s.executeCommand(ch, requests, state, payload.Command)
			return

		case "shell":
			replyRequest(req, true)
			s.executeCommand(ch, requests, state, "")
			return

		case "window-change":
			// Handled during command execution; ignore here.
			replyRequest(req, false)

		default:
			s.logger.Debug("unhandled session request", "type", req.Type)
			replyRequest(req, false)
		}
	}
}

// executeCommand builds and runs a command in the configured environment.
// An empty command string starts a login shell.
func (s *Server) executeCommand(ch ssh.Channel, requests <-chan *ssh.Request, state *sessionState, command string) {
	env := s.buildEnv(state)

	var cmd *exec.Cmd
	if command == "" {
		// Login shell.
		cmd = exec.Command(s.cfg.DefaultShell, "-l")
	} else {
		cmd = exec.Command(s.cfg.DefaultShell, "-c", command)
	}

	cmd.Env = env

	// Determine working directory: prefer DefaultWorkDir, fall back to DefaultHome.
	workDir := s.cfg.DefaultWorkDir
	if workDir == "" {
		workDir = s.cfg.DefaultHome
	}
	if workDir != "" {
		if _, err := os.Stat(workDir); err != nil {
			s.logger.Debug("work dir unavailable, falling back to home",
				"workdir", workDir,
				"home", s.cfg.DefaultHome,
				"error", err,
			)
			workDir = s.cfg.DefaultHome
		}
	}
	cmd.Dir = workDir

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	// Only set credentials when the target UID/GID differs from the
	// current process. Setting Credential requires CAP_SETUID/CAP_SETGID
	// which is typically only available to root (e.g. inside the guest VM
	// init process).
	if s.cfg.DefaultUID != uint32(os.Getuid()) || s.cfg.DefaultGID != uint32(os.Getgid()) {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid: s.cfg.DefaultUID,
			Gid: s.cfg.DefaultGID,
		}
	}

	var exitStatus int
	if state.ptyReq != nil {
		exitStatus = s.runWithPTY(ch, requests, cmd, state.ptyReq)
	} else {
		exitStatus = s.runWithoutPTY(ch, requests, cmd)
	}

	sendExitStatus(ch, exitStatus)
}

// buildEnv merges the base environment with session-specific overrides.
func (s *Server) buildEnv(state *sessionState) []string {
	env := make([]string, len(s.cfg.Env))
	copy(env, s.cfg.Env)

	// Add standard identity variables.
	env = append(env,
		"USER="+s.cfg.DefaultUser,
		"HOME="+s.cfg.DefaultHome,
		"SHELL="+s.cfg.DefaultShell,
	)

	// Apply session-specific overrides (client "env" requests + TERM).
	for k, v := range state.env {
		env = append(env, k+"="+v)
	}

	return env
}

// runWithPTY executes the command with a pseudo-terminal, handling
// bidirectional I/O, window-change events, and signal forwarding.
func (s *Server) runWithPTY(ch ssh.Channel, requests <-chan *ssh.Request, cmd *exec.Cmd, pr *ptyRequest) int {
	ptmx, err := pty.Start(cmd)
	if err != nil {
		s.logger.Error("start pty", "error", err)
		return 1
	}
	defer func() { _ = ptmx.Close() }()

	// Apply the initial window size.
	setWinsize(ptmx, pr.Width, pr.Height)

	// Handle ongoing requests (window-change, signal) in the background.
	go func() {
		for req := range requests {
			switch req.Type {
			case "window-change":
				var wc windowChangeRequest
				if err := ssh.Unmarshal(req.Payload, &wc); err != nil {
					s.logger.Warn("malformed window-change", "error", err)
					continue
				}
				setWinsize(ptmx, wc.Width, wc.Height)
			case "signal":
				s.signalProcess(cmd, req)
			default:
				replyRequest(req, false)
			}
		}
	}()

	// Bidirectional copy between the SSH channel and the PTY.
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(ptmx, ch)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch, ptmx)
	}()

	err = cmd.Wait()
	// Close the PTY to unblock the copy goroutines.
	_ = ptmx.Close()
	wg.Wait()

	return exitCode(err)
}

// runWithoutPTY executes the command with direct stdin/stdout/stderr
// piping, handling signal forwarding.
func (s *Server) runWithoutPTY(ch ssh.Channel, requests <-chan *ssh.Request, cmd *exec.Cmd) int {
	cmd.Stdin = ch
	cmd.Stdout = ch
	cmd.Stderr = ch.Stderr()

	if err := cmd.Start(); err != nil {
		s.logger.Error("start command", "error", err)
		return 1
	}

	// Handle ongoing requests in the background.
	go func() {
		for req := range requests {
			switch req.Type {
			case "signal":
				s.signalProcess(cmd, req)
			default:
				replyRequest(req, false)
			}
		}
	}()

	err := cmd.Wait()
	return exitCode(err)
}

// signalProcess forwards an SSH "signal" request to the running process.
func (s *Server) signalProcess(cmd *exec.Cmd, req *ssh.Request) {
	var sr signalRequest
	if err := ssh.Unmarshal(req.Payload, &sr); err != nil {
		s.logger.Warn("malformed signal request", "error", err)
		return
	}

	sig, ok := sshSignalToOS[sr.Signal]
	if !ok {
		s.logger.Warn("unknown SSH signal", "signal", sr.Signal)
		return
	}

	if cmd.Process != nil {
		if err := cmd.Process.Signal(sig); err != nil {
			s.logger.Warn("signal process failed",
				"signal", sr.Signal,
				"pid", cmd.Process.Pid,
				"error", err,
			)
		}
	}
}

// sendExitStatus sends the "exit-status" message on the SSH channel and
// closes the channel.
func sendExitStatus(ch ssh.Channel, code int) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(code))
	//nolint:errcheck // Best-effort delivery; the channel may already be closed.
	_, _ = ch.SendRequest("exit-status", false, payload)
	_ = ch.Close()
}

// exitCode extracts the numeric exit code from the error returned by
// exec.Cmd.Wait().
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return 1
}

// setWinsize sets the terminal window size on the given PTY file descriptor.
//
//nolint:revive // Underscores in struct field names match the kernel ioctl struct.
func setWinsize(f *os.File, width, height uint32) {
	ws := struct {
		ws_row    uint16
		ws_col    uint16
		ws_xpixel uint16
		ws_ypixel uint16
	}{
		ws_row: uint16(height),
		ws_col: uint16(width),
	}
	//nolint:gosec // TIOCSWINSZ ioctl requires unsafe.Pointer.
	_, _, _ = syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TIOCSWINSZ,
		uintptr(unsafe.Pointer(&ws)),
	)
}

// replyRequest replies to an SSH request only if the client expects a
// reply.
func replyRequest(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}
