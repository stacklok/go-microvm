// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package preflight

import (
	"context"
	"fmt"
	"os"
	"syscall"
)

const kvmDevicePath = "/dev/kvm"

// registerPlatformChecks adds Linux-specific preflight checks.
func registerPlatformChecks(c *checker) {
	c.Register(Check{
		Name:        "kvm",
		Description: "Verify KVM is available and accessible",
		Run:         checkKVM,
		Required:    true,
	})

	// Add resource checks as non-required (advisory) defaults.
	c.Register(DiskSpaceCheck("", 2.0))
	c.Register(ResourceCheck(1, 1.0))
}

// checkKVM verifies that /dev/kvm exists, is a character device, and is
// accessible by the current user.
func checkKVM(_ context.Context) error {
	info, err := os.Stat(kvmDevicePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%s does not exist: ensure KVM kernel modules are loaded "+
				"(try: sudo modprobe kvm kvm_intel or sudo modprobe kvm kvm_amd)", kvmDevicePath)
		}
		return fmt.Errorf("failed to stat %s: %w", kvmDevicePath, err)
	}

	// Verify it is a character device.
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("unexpected stat type for %s", kvmDevicePath)
	}

	if stat.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return fmt.Errorf("%s exists but is not a character device", kvmDevicePath)
	}

	// Verify we can open it for read/write.
	f, err := os.OpenFile(kvmDevicePath, os.O_RDWR, 0)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("permission denied accessing %s: add your user to the 'kvm' group "+
				"(try: sudo usermod -aG kvm $USER) and log out/in, or run as root", kvmDevicePath)
		}
		return fmt.Errorf("cannot open %s: %w", kvmDevicePath, err)
	}
	_ = f.Close()

	return nil
}
