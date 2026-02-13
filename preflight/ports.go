// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package preflight

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

// portChecker holds injectable dependencies for port availability checks.
type portChecker struct {
	listen     func(network, address string) (net.Listener, error)
	commandCtx func(ctx context.Context, name string, arg ...string) *exec.Cmd
}

func newPortChecker() *portChecker {
	return &portChecker{
		listen:     net.Listen,
		commandCtx: exec.CommandContext,
	}
}

// PortCheck creates a preflight Check that verifies the given TCP ports are
// available for binding on localhost. If any port is already in use, the
// check returns an error with details about which process holds the port
// (when available).
func PortCheck(ports ...uint16) Check {
	pc := newPortChecker()
	return Check{
		Name:        "ports",
		Description: fmt.Sprintf("Verify ports %v are available", ports),
		Run: func(ctx context.Context) error {
			return pc.checkPorts(ctx, ports)
		},
		Required: true,
	}
}

// checkPorts verifies that all specified ports are available for binding.
func (pc *portChecker) checkPorts(ctx context.Context, ports []uint16) error {
	var errs []string

	for _, port := range ports {
		if err := pc.checkPortAvailable(ctx, port); err != nil {
			errs = append(errs, err.Error())
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("ports in use:\n  %s", strings.Join(errs, "\n  "))
	}

	return nil
}

// checkPortAvailable attempts to bind to the given TCP port on localhost.
// If the port is in use, it returns an error with process information
// when available.
func (pc *portChecker) checkPortAvailable(ctx context.Context, port uint16) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := pc.listen("tcp", addr)
	if err != nil {
		// Port is in use. Try to get process info.
		processInfo := pc.getPortProcessInfo(ctx, port)
		if processInfo != "" {
			return fmt.Errorf("port %d is already in use by: %s", port, processInfo)
		}
		return fmt.Errorf("port %d is already in use", port)
	}

	_ = ln.Close()
	return nil
}

// getPortProcessInfo attempts to determine which process is using a port.
// It uses the `ss` command on Linux. Returns an empty string if the
// information cannot be determined.
func (pc *portChecker) getPortProcessInfo(ctx context.Context, port uint16) string {
	// Try ss (modern Linux). The filter expression must be a single argument.
	//nolint:gosec // port is a uint16, not user-controlled string
	out, err := pc.commandCtx(ctx, "ss", "-tlnp",
		fmt.Sprintf("sport = :%d", port)).CombinedOutput()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for _, line := range lines {
			if !strings.Contains(line, "LISTEN") {
				continue
			}
			// Parse users:(("name",pid=NNN,fd=N)) to extract process info.
			if idx := strings.Index(line, "users:(("); idx != -1 {
				start := idx + len("users:((")
				end := strings.Index(line[start:], "))")
				if end != -1 {
					info := line[start : start+end]
					parts := strings.Split(info, ",")
					if len(parts) >= 2 {
						procName := strings.Trim(parts[0], "\"")
						pid := strings.TrimPrefix(parts[1], "pid=")
						return fmt.Sprintf("%s (pid %s)", procName, pid)
					}
					return info
				}
			}
			return "process listening"
		}
	}

	return ""
}
