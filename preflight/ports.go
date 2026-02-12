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

// PortCheck creates a preflight Check that verifies the given TCP ports are
// available for binding on localhost. If any port is already in use, the
// check returns an error with details about which process holds the port
// (when available).
func PortCheck(ports ...uint16) Check {
	return Check{
		Name:        "ports",
		Description: fmt.Sprintf("Verify ports %v are available", ports),
		Run: func(ctx context.Context) error {
			return checkPorts(ctx, ports)
		},
		Required: true,
	}
}

// checkPorts verifies that all specified ports are available for binding.
func checkPorts(ctx context.Context, ports []uint16) error {
	var errs []string

	for _, port := range ports {
		if err := checkPortAvailable(ctx, port); err != nil {
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
func checkPortAvailable(ctx context.Context, port uint16) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		// Port is in use. Try to get process info.
		processInfo := getPortProcessInfo(ctx, port)
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
func getPortProcessInfo(ctx context.Context, port uint16) string {
	// Try ss (modern Linux).
	//nolint:gosec // port is a uint16, not user-controlled string
	out, err := exec.CommandContext(ctx, "ss", "-tlnp",
		"sport", "=", fmt.Sprintf(":%d", port)).CombinedOutput()
	if err == nil {
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		// Skip header line; return the first data line if present.
		if len(lines) > 1 {
			return strings.TrimSpace(lines[1])
		}
	}

	return ""
}
