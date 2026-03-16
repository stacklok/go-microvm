// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package microvm

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stacklok/go-microvm/hypervisor"
	"github.com/stacklok/go-microvm/net"
	"github.com/stacklok/go-microvm/state"
)

// VM represents a running microVM.
type VM struct {
	name       string
	handle     hypervisor.VMHandle
	netProv    net.Provider
	dataDir    string
	rootfsPath string
	ports      []PortForward
	cacheDir   string
	removeAll  func(string) error
}

// VMInfo contains status information about a VM.
type VMInfo struct {
	Name      string
	Active    bool
	PID       int    // kept for state compatibility, populated via pidFromID
	ID        string // backend-specific identifier
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

	if err := vm.handle.Stop(ctx); err != nil {
		return fmt.Errorf("stop vm process: %w", err)
	}

	if vm.netProv != nil {
		vm.netProv.Stop()
	}

	// Best-effort state cleanup. Use context.Background() so cleanup
	// succeeds even if the caller's context is already canceling.
	// Use LoadAndLockWithRetry with a bounded timeout so Stop() never
	// blocks forever if something unexpected holds the flock.
	if vm.dataDir != "" {
		stateMgr := state.NewManager(vm.dataDir)
		if ls, stateErr := stateMgr.LoadAndLockWithRetry(context.Background(), 10*time.Second); stateErr == nil {
			defer ls.Release()
			ls.State.Active = false
			ls.State.PID = 0
			if saveErr := ls.Save(); saveErr != nil {
				slog.Warn("failed to persist state during stop", "error", saveErr)
			}
		}
	}

	return nil
}

// Status returns current information about the VM.
func (vm *VM) Status(_ context.Context) (*VMInfo, error) {
	alive := vm.handle.IsAlive()
	id := vm.handle.ID()
	pid, _ := pidFromID(id)
	return &VMInfo{
		Name:   vm.name,
		Active: alive,
		PID:    pid,
		ID:     id,
		Ports:  vm.ports,
	}, nil
}

// Remove stops the VM and cleans up its rootfs and state.
// If the image cache lives under the data dir, its contents are preserved.
func (vm *VM) Remove(ctx context.Context) error {
	// Always attempt Stop — it is idempotent and handles already-dead VMs.
	// This avoids a TOCTOU race between IsAlive() and Stop().
	if err := vm.Stop(ctx); err != nil {
		return fmt.Errorf("stop before remove: %w", err)
	}
	if vm.removeAll == nil {
		vm.removeAll = os.RemoveAll
	}

	if vm.rootfsPath != "" && !isWithin(vm.cacheDir, vm.rootfsPath) {
		if err := vm.removeAll(vm.rootfsPath); err != nil {
			return fmt.Errorf("remove rootfs: %w", err)
		}
	}

	if vm.dataDir != "" {
		var keep []string
		if vm.cacheDir != "" && isWithin(vm.dataDir, vm.cacheDir) {
			keep = append(keep, vm.cacheDir)
		}
		if len(keep) > 0 {
			if err := removeDataDirContentsExcept(vm.removeAll, vm.dataDir, keep); err != nil {
				return fmt.Errorf("remove data dir contents: %w", err)
			}
		} else {
			if err := vm.removeAll(vm.dataDir); err != nil {
				return fmt.Errorf("remove data dir: %w", err)
			}
		}
	}

	return nil
}

// RunnerPID returns the runner process ID, or 0 if the ID cannot be parsed
// as a PID (e.g. non-process-based backends).
// Because the runner starts with Setsid: true, its PGID equals its PID.
// Callers needing process-group signals can use syscall.Kill(-pid, sig).
func (vm *VM) RunnerPID() int {
	pid, err := pidFromID(vm.handle.ID())
	if err != nil {
		return 0
	}
	return pid
}

// Name returns the VM name.
func (vm *VM) Name() string { return vm.name }

// ID returns the backend-specific VM identifier.
func (vm *VM) ID() string { return vm.handle.ID() }

// DataDir returns the base data directory for this VM.
func (vm *VM) DataDir() string { return vm.dataDir }

// RootFSPath returns the path to the extracted rootfs directory.
func (vm *VM) RootFSPath() string { return vm.rootfsPath }

// Ports returns the configured port forwards.
func (vm *VM) Ports() []PortForward { return vm.ports }

func isWithin(base string, target string) bool {
	if base == "" || target == "" {
		return false
	}
	rel, err := filepath.Rel(base, target)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func removeDataDirContentsExcept(removeAll func(string) error, dataDir string, keepPaths []string) error {
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return fmt.Errorf("read data dir: %w", err)
	}
	keep := make(map[string]struct{}, len(keepPaths))
	for _, path := range keepPaths {
		if path == "" {
			continue
		}
		keep[filepath.Clean(path)] = struct{}{}
	}
	for _, entry := range entries {
		entryPath := filepath.Join(dataDir, entry.Name())
		if _, ok := keep[filepath.Clean(entryPath)]; ok {
			continue
		}
		if err := removeAll(entryPath); err != nil {
			return fmt.Errorf("remove data dir entry %s: %w", entryPath, err)
		}
	}
	return nil
}
