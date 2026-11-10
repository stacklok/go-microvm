// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package preflight

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type memoryStatusEx struct {
	length               uint32
	memoryLoad           uint32
	totalPhys            uint64
	availPhys            uint64
	totalPageFile        uint64
	availPageFile        uint64
	totalVirtual         uint64
	availVirtual         uint64
	availExtendedVirtual uint64
}

type resourceChecker struct {
	getDiskFreeSpace func(path string) (uint64, error)
	getTotalMemory   func() (uint64, error)
	numCPU           func() int
}

func newResourceChecker() *resourceChecker {
	return &resourceChecker{
		getDiskFreeSpace: windowsDiskFreeSpace,
		getTotalMemory:   windowsTotalMemory,
		numCPU:           runtime.NumCPU,
	}
}

// DiskSpaceCheck returns an advisory disk-space check for Windows.
func DiskSpaceCheck(dataDir string, minFreeGB float64) Check {
	resources := newResourceChecker()
	return Check{
		Name:        "disk-space",
		Description: fmt.Sprintf("Verify at least %.1f GB free disk space", minFreeGB),
		Run: func(_ context.Context) error {
			return resources.checkDiskSpace(dataDir, minFreeGB)
		},
		Required: false,
	}
}

func (rc *resourceChecker) checkDiskSpace(dataDir string, minFreeGB float64) error {
	dir := dataDir
	if dir == "" {
		dir = filepath.VolumeName(os.TempDir()) + `\`
	}
	for {
		info, err := os.Stat(dir)
		if err == nil && info.IsDir() {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	freeBytes, err := rc.getDiskFreeSpace(dir)
	if err != nil {
		return fmt.Errorf("cannot check disk space on %s: %w", dir, err)
	}
	freeGB := float64(freeBytes) / (1024 * 1024 * 1024)
	if freeGB < minFreeGB {
		return fmt.Errorf(
			"insufficient disk space: %.1f GB available on %s, %.1f GB recommended",
			freeGB,
			dir,
			minFreeGB,
		)
	}
	return nil
}

// ResourceCheck returns an advisory CPU and memory check for Windows.
func ResourceCheck(minCPUs int, minMemoryGiB float64) Check {
	resources := newResourceChecker()
	return Check{
		Name:        "resources",
		Description: fmt.Sprintf("Verify minimum resources (%d CPUs, %.1f GiB RAM)", minCPUs, minMemoryGiB),
		Run: func(_ context.Context) error {
			return resources.checkResources(minCPUs, minMemoryGiB)
		},
		Required: false,
	}
}

func (rc *resourceChecker) checkResources(minCPUs int, minMemoryGiB float64) error {
	cpuCores := rc.numCPU()
	if cpuCores < minCPUs {
		return fmt.Errorf("CPU cores (%d) is below recommended minimum (%d)", cpuCores, minCPUs)
	}
	memoryBytes, err := rc.getTotalMemory()
	if err != nil {
		return fmt.Errorf("cannot check system memory: %w", err)
	}
	memoryGiB := float64(memoryBytes) / (1024 * 1024 * 1024)
	if memoryGiB < minMemoryGiB {
		return fmt.Errorf(
			"total memory (%.1f GiB) is below recommended minimum (%.1f GiB)",
			memoryGiB,
			minMemoryGiB,
		)
	}
	return nil
}

func windowsDiskFreeSpace(path string) (uint64, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, fmt.Errorf("encode disk path: %w", err)
	}
	var freeBytes uint64
	if err := windows.GetDiskFreeSpaceEx(pathPointer, &freeBytes, nil, nil); err != nil {
		return 0, fmt.Errorf("get disk free space: %w", err)
	}
	return freeBytes, nil
}

func windowsTotalMemory() (uint64, error) {
	status := memoryStatusEx{length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	result, _, callErr := proc.Call(uintptr(unsafe.Pointer(&status)))
	if result == 0 {
		if callErr == syscall.Errno(0) {
			callErr = syscall.EINVAL
		}
		return 0, fmt.Errorf("GlobalMemoryStatusEx: %w", callErr)
	}
	return status.totalPhys, nil
}
