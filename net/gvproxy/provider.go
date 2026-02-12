// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package gvproxy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/stacklok/propolis/net"
)

const (
	// guestIP is the default guest IP assigned by gvproxy's built-in DHCP.
	guestIP = "192.168.127.2"

	// localhost is the default host address for port forwards.
	localhost = "127.0.0.1"

	// sockName is the filename for the gvproxy Unix socket.
	sockName = "gvproxy.sock"

	// logName is the filename for gvproxy log output.
	logName = "gvproxy.log"

	// configName is the filename for the gvproxy YAML config.
	configName = "gvproxy.yaml"

	// socketWaitTimeout is how long we wait for the gvproxy socket to appear.
	socketWaitTimeout = 10 * time.Second

	// socketPollInterval is the interval between polls for the socket file.
	socketPollInterval = 100 * time.Millisecond
)

// Provider is a [net.Provider] backed by gvproxy.
//
// gvproxy provides usermode networking (DHCP, DNS, port forwarding) via a Unix
// stream socket that connects to libkrun's virtio-net device. The provider
// writes a YAML config file and launches gvproxy with -config pointing at it.
type Provider struct {
	binaryPath string
	sockPath   string
	configPath string
	pid        int
	cmd        *exec.Cmd
	dataDir    string
}

// New creates a new gvproxy Provider. It locates the gvproxy binary
// on the system PATH. The dataDir is used to store the Unix socket,
// YAML config, and log files.
func New(dataDir string) *Provider {
	binaryPath, err := exec.LookPath("gvproxy")
	if err != nil {
		// Store empty path; Start will fail with a clear error.
		slog.Warn("gvproxy binary not found in PATH", "error", err)
	}

	return &Provider{
		binaryPath: binaryPath,
		dataDir:    dataDir,
	}
}

// Start launches gvproxy as a detached process with the given configuration.
//
// It writes a YAML config file with interfaces.qemu (the listen socket) and
// stack.forwards (port forwarding map), then starts gvproxy with -config
// pointing at that file. The socket path is derived from dataDir.
//
// We use interfaces.qemu because both gvproxy's QEMU transport and libkrun's
// krun_add_net_unixstream use identical wire format: SOCK_STREAM with 4-byte
// big-endian length prefix per Ethernet frame. The vfkit transport (unixgram)
// is macOS-only in gvproxy, but the QEMU transport works on all platforms.
func (p *Provider) Start(_ context.Context, cfg net.Config) error {
	if p.binaryPath == "" {
		return fmt.Errorf("gvproxy binary not found: ensure gvproxy is installed and in PATH")
	}

	if err := os.MkdirAll(p.dataDir, 0o700); err != nil {
		return fmt.Errorf("create gvproxy data dir: %w", err)
	}

	p.sockPath = filepath.Join(p.dataDir, sockName)
	p.configPath = filepath.Join(p.dataDir, configName)

	// Remove any stale socket file from a previous run.
	if err := os.Remove(p.sockPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale gvproxy socket: %w", err)
	}

	// Write gvproxy YAML config file with listen endpoint and port forwards.
	if err := p.writeConfig(cfg.Forwards); err != nil {
		return fmt.Errorf("write gvproxy config: %w", err)
	}

	// gvproxy is launched with -config pointing at the YAML file.
	// All networking configuration (listen socket, port forwards) is in the config.
	args := []string{"-config", p.configPath}

	slog.Debug("starting gvproxy",
		"binary", p.binaryPath,
		"args", args,
		"sockPath", p.sockPath,
		"configPath", p.configPath,
	)

	cmd := exec.Command(p.binaryPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true, // Detach from terminal (new session)
	}

	// Log output to file.
	logPath := filepath.Join(p.dataDir, logName)
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open gvproxy log file: %w", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start gvproxy: %w", err)
	}

	_ = logFile.Close()

	p.cmd = cmd
	p.pid = cmd.Process.Pid

	slog.Info("gvproxy started",
		"pid", p.pid,
		"sockPath", p.sockPath,
		"portForwards", len(cfg.Forwards),
	)

	// Wait for the socket to appear before returning.
	if err := p.waitForSocket(); err != nil {
		p.Stop()
		return fmt.Errorf("waiting for gvproxy socket: %w", err)
	}

	return nil
}

// writeConfig writes a gvproxy YAML config file.
// Format documented at https://github.com/containers/gvisor-tap-vsock
//
// The config uses interfaces.qemu to specify the Unix socket endpoint
// and stack.forwards as a map of "host_ip:host_port" -> "guest_ip:guest_port"
// for TCP port forwarding between host and guest.
func (p *Provider) writeConfig(ports []net.PortForward) error {
	// Build the forwards map: "127.0.0.1:<host>" -> "<guest_ip>:<guest>"
	forwards := ""
	for _, pf := range ports {
		forwards += fmt.Sprintf("    \"%s:%d\": \"%s:%d\"\n",
			localhost, pf.Host, guestIP, pf.Guest)
	}

	config := fmt.Sprintf(`interfaces:
  qemu: unix://%s
stack:
  forwards:
%s`, p.sockPath, forwards)

	return os.WriteFile(p.configPath, []byte(config), 0o644)
}

// SocketPath returns the Unix socket path for the gvproxy listen socket.
// The runner passes this path to krun_add_net_unixstream(ctx, path, -1, ...).
func (p *Provider) SocketPath() string {
	return p.sockPath
}

// PID returns the process ID of the gvproxy instance, or 0 if not running.
func (p *Provider) PID() int {
	return p.pid
}

// Stop terminates the gvproxy process and cleans up the socket file.
func (p *Provider) Stop() {
	if p.cmd == nil || p.cmd.Process == nil {
		return
	}

	slog.Debug("stopping gvproxy", "pid", p.pid)

	// Send SIGTERM for graceful shutdown.
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		slog.Debug("SIGTERM to gvproxy failed, trying SIGKILL", "error", err)
		_ = p.cmd.Process.Kill()
	}

	// Reap the process to avoid zombies.
	_, _ = p.cmd.Process.Wait()

	// Clean up the socket file.
	if p.sockPath != "" {
		if err := os.Remove(p.sockPath); err != nil && !os.IsNotExist(err) {
			slog.Debug("failed to remove gvproxy socket", "error", err)
		}
	}

	p.pid = 0
	p.cmd = nil
}

// waitForSocket polls until the gvproxy Unix socket file appears on disk.
func (p *Provider) waitForSocket() error {
	deadline := time.After(socketWaitTimeout)
	ticker := time.NewTicker(socketPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-deadline:
			return fmt.Errorf("timeout after %s waiting for gvproxy socket at %s",
				socketWaitTimeout, p.sockPath)
		case <-ticker.C:
			if _, err := os.Stat(p.sockPath); err == nil {
				slog.Debug("gvproxy socket ready", "path", p.sockPath)
				return nil
			}

			// Check if the process died.
			if p.cmd.ProcessState != nil {
				return fmt.Errorf("gvproxy exited prematurely with code %d",
					p.cmd.ProcessState.ExitCode())
			}
		}
	}
}
