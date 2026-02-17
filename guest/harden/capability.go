// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package harden

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Linux capability constants. Only the subset typically needed by guest
// init processes is defined here.
const (
	CapChown          uintptr = 0
	CapSetUID         uintptr = 7
	CapSetGID         uintptr = 6
	CapKill           uintptr = 5
	CapNetBindService uintptr = 10
)

// prctl constants for capability bounding set manipulation.
const (
	prCapBSetDrop = 24 // PR_CAPBSET_DROP
)

// capLastCap reads the highest valid capability number from
// /proc/sys/kernel/cap_last_cap. Falls back to 41 (CAP_CHECKPOINT_RESTORE,
// the highest cap on Linux 6.x kernels) if the file is unreadable.
func capLastCap() uintptr {
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 41
	}
	n, err := parseCapLastCap(string(data))
	if err != nil {
		return 41
	}
	return n
}

// parseCapLastCap parses the content of /proc/sys/kernel/cap_last_cap.
func parseCapLastCap(content string) (uintptr, error) {
	n, err := strconv.Atoi(strings.TrimSpace(content))
	if err != nil {
		return 0, fmt.Errorf("parsing cap_last_cap: %w", err)
	}
	return uintptr(n), nil
}

// DropBoundingCaps drops all capabilities from the bounding set except
// those listed in keep. This limits what capabilities child processes
// can acquire even through setuid binaries or file capabilities.
//
// Call this as the last privileged operation before starting the
// workload — all mounts, network config, and chown calls must be
// complete before caps are dropped.
func DropBoundingCaps(keep ...uintptr) error {
	keepSet := make(map[uintptr]struct{}, len(keep))
	for _, c := range keep {
		keepSet[c] = struct{}{}
	}

	last := capLastCap()
	for cap := uintptr(0); cap <= last; cap++ {
		if _, ok := keepSet[cap]; ok {
			continue
		}
		if err := capBSetDrop(cap); err != nil {
			return fmt.Errorf("dropping cap %d: %w", cap, err)
		}
	}
	return nil
}

// capBSetDrop calls prctl(PR_CAPBSET_DROP, cap) to remove a single
// capability from the bounding set.
func capBSetDrop(cap uintptr) error {
	_, _, errno := syscall.Syscall(
		syscall.SYS_PRCTL,
		prCapBSetDrop,
		cap,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("prctl(PR_CAPBSET_DROP, %d): %w", cap, errno)
	}
	return nil
}

// keepSetContains reports whether cap is in the given keep set.
func keepSetContains(keep []uintptr, cap uintptr) bool {
	for _, k := range keep {
		if k == cap {
			return true
		}
	}
	return false
}
