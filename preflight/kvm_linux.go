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

// kvmChecker holds injectable dependencies for KVM verification.
type kvmChecker struct {
	stat     func(string) (os.FileInfo, error)
	openFile func(string, int, os.FileMode) (*os.File, error)
}

func newKVMChecker() *kvmChecker {
	return &kvmChecker{
		stat:     os.Stat,
		openFile: os.OpenFile,
	}
}

// registerPlatformChecks adds Linux-specific preflight checks.
func registerPlatformChecks(c *checker) {
	kvm := newKVMChecker()
	c.Register(Check{
		Name:        "kvm",
		Description: "Verify KVM is available and accessible",
		Run:         kvm.check,
		Required:    true,
	})

	// CAP_CHOWN check — without it, extracted rootfs ownership will be wrong.
	chown := newChownChecker()
	c.Register(Check{
		Name:        "cap-chown",
		Description: "Verify process can chown files (root or CAP_CHOWN)",
		Run:         chown.check,
		Required:    false,
	})

	// Add resource checks as non-required (advisory) defaults.
	c.Register(DiskSpaceCheck("", 2.0))
	c.Register(ResourceCheck(1, 1.0))
}

// check verifies that /dev/kvm exists, is a character device, and is
// accessible by the current user.
func (k *kvmChecker) check(_ context.Context) error {
	info, err := k.stat(kvmDevicePath)
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
	f, err := k.openFile(kvmDevicePath, os.O_RDWR, 0)
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
