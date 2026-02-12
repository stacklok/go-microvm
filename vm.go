// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/stacklok/propolis/net"
	"github.com/stacklok/propolis/runner"
)

// VM represents a running microVM.
type VM struct {
	name       string
	proc       *runner.Process
	netProv    net.Provider
	dataDir    string
	rootfsPath string
	ports      []PortForward
}

// VMInfo contains status information about a VM.
type VMInfo struct {
	Name      string
	Active    bool
	PID       int
	CPUs      uint32
	Memory    uint32
	Ports     []PortForward
	CreatedAt time.Time
}

// Stop gracefully shuts down the VM. It sends SIGTERM and waits for the
// process to exit. If the process doesn't exit within 30 seconds, it is
// forcefully killed.
func (vm *VM) Stop(ctx context.Context) error {
	slog.Info("stopping VM", "name", vm.name)

	if err := vm.proc.Stop(ctx); err != nil {
		return fmt.Errorf("stop vm process: %w", err)
	}

	vm.netProv.Stop()
	return nil
}

// Status returns current information about the VM.
func (vm *VM) Status(_ context.Context) (*VMInfo, error) {
	alive := vm.proc.IsAlive()
	return &VMInfo{
		Name:   vm.name,
		Active: alive,
		PID:    vm.proc.PID,
		Ports:  vm.ports,
	}, nil
}

// Remove stops the VM and cleans up its rootfs and state.
func (vm *VM) Remove(ctx context.Context) error {
	if vm.proc.IsAlive() {
		if err := vm.Stop(ctx); err != nil {
			return fmt.Errorf("stop before remove: %w", err)
		}
	}
	// Note: we intentionally do NOT remove the image cache —
	// only the VM-specific state and rootfs extraction.
	return nil
}

// Name returns the VM name.
func (vm *VM) Name() string { return vm.name }

// PID returns the runner process ID.
func (vm *VM) PID() int { return vm.proc.PID }

// DataDir returns the base data directory for this VM.
func (vm *VM) DataDir() string { return vm.dataDir }

// RootFSPath returns the path to the extracted rootfs directory.
func (vm *VM) RootFSPath() string { return vm.rootfsPath }

// Ports returns the configured port forwards.
func (vm *VM) Ports() []PortForward { return vm.ports }

// NetProviderPID returns the process ID of the network provider (e.g., gvproxy).
func (vm *VM) NetProviderPID() int { return vm.netProv.PID() }
