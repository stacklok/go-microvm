// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package preflight

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// resourceChecker holds injectable dependencies for resource verification.
type resourceChecker struct {
	statfs       func(path string, buf *syscall.Statfs_t) error
	sysctlUint64 func(name string) (uint64, error)
	numCPU       func() int
}

func newResourceChecker() *resourceChecker {
	return &resourceChecker{
		statfs: syscall.Statfs,
		sysctlUint64: func(name string) (uint64, error) {
			return unix.SysctlUint64(name)
		},
		numCPU: runtime.NumCPU,
	}
}

// DiskSpaceCheck returns an advisory Check that verifies at least minFreeGB
// of disk space is available on the filesystem containing dataDir.
// If dataDir does not exist yet, the check walks up the directory tree
// to find the nearest existing ancestor and checks that filesystem instead.
// An empty dataDir defaults to "/".
func DiskSpaceCheck(dataDir string, minFreeGB float64) Check {
	rc := newResourceChecker()
	return Check{
		Name:        "disk-space",
		Description: fmt.Sprintf("Verify at least %.1f GB free disk space", minFreeGB),
		Run: func(_ context.Context) error {
			return rc.checkDiskSpace(dataDir, minFreeGB)
		},
		Required: false,
	}
}

// checkDiskSpace verifies sufficient free disk space at the given path.
func (rc *resourceChecker) checkDiskSpace(dataDir string, minFreeGB float64) error {
	dir := dataDir
	if dir == "" {
		dir = "/"
	}

	// Walk up the directory tree until we find an existing directory.
	for {
		info, err := os.Stat(dir)
		if err == nil && info.IsDir() {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached the root, stop.
			break
		}
		dir = parent
	}

	var stat syscall.Statfs_t
	if err := rc.statfs(dir, &stat); err != nil {
		return fmt.Errorf("cannot check disk space on %s: %w", dir, err)
	}

	freeGB := float64(stat.Bavail) * float64(stat.Bsize) / (1024 * 1024 * 1024)
	if freeGB < minFreeGB {
		return fmt.Errorf("insufficient disk space: %.1f GB available on %s, %.1f GB recommended",
			freeGB, dir, minFreeGB)
	}

	return nil
}

// ResourceCheck returns an advisory Check that verifies the host has at least
// minCPUs logical CPU cores and minMemoryGiB of total RAM.
func ResourceCheck(minCPUs int, minMemoryGiB float64) Check {
	rc := newResourceChecker()
	return Check{
		Name:        "resources",
		Description: fmt.Sprintf("Verify minimum resources (%d CPUs, %.1f GiB RAM)", minCPUs, minMemoryGiB),
		Run: func(_ context.Context) error {
			return rc.checkResources(minCPUs, minMemoryGiB)
		},
		Required: false,
	}
}

// checkResources verifies CPU and memory meet minimum requirements.
func (rc *resourceChecker) checkResources(minCPUs int, minMemoryGiB float64) error {
	cpuCores := rc.numCPU()
	if cpuCores < minCPUs {
		return fmt.Errorf("CPU cores (%d) is below recommended minimum (%d)", cpuCores, minCPUs)
	}

	memBytes, err := rc.sysctlUint64("hw.memsize")
	if err != nil {
		return fmt.Errorf("cannot check system memory: %w", err)
	}

	memGiB := float64(memBytes) / (1024 * 1024 * 1024)
	if memGiB < minMemoryGiB {
		return fmt.Errorf("total memory (%.1f GiB) is below recommended minimum (%.1f GiB)",
			memGiB, minMemoryGiB)
	}

	return nil
}
