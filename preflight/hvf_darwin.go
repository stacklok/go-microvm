// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package preflight

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// hvfChecker holds injectable dependencies for Hypervisor.framework verification.
type hvfChecker struct {
	sysctlUint32 func(name string) (uint32, error)
}

func newHVFChecker() *hvfChecker {
	return &hvfChecker{
		sysctlUint32: unix.SysctlUint32,
	}
}

// registerPlatformChecks adds macOS-specific preflight checks.
func registerPlatformChecks(c *checker) {
	hvf := newHVFChecker()
	c.Register(Check{
		Name:        "hvf",
		Description: "Verify Hypervisor.framework is available",
		Run:         hvf.check,
		Required:    true,
	})

	// Add resource checks as non-required (advisory) defaults.
	c.Register(DiskSpaceCheck("", 2.0))
	c.Register(ResourceCheck(1, 1.0))
}

// check verifies that Hypervisor.framework is available by reading the
// kern.hv_support sysctl. A value of 1 means the hypervisor is supported.
func (h *hvfChecker) check(_ context.Context) error {
	val, err := h.sysctlUint32("kern.hv_support")
	if err != nil {
		return fmt.Errorf("cannot check Hypervisor.framework support "+
			"(try: sysctl kern.hv_support): %w", err)
	}

	if val != 1 {
		return fmt.Errorf("hypervisor framework is not available (kern.hv_support=%d): "+
			"Apple Silicon Mac required", val)
	}

	return nil
}
