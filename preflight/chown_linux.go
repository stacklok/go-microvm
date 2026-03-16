// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package preflight

import (
	"context"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// chownChecker holds injectable dependencies for CAP_CHOWN verification.
type chownChecker struct {
	getuid func() int
	capget func() (uint32, error)
}

func newChownChecker() *chownChecker {
	return &chownChecker{
		getuid: os.Getuid,
		capget: getEffectiveCaps,
	}
}

// check verifies that the current process can chown files, either by
// running as root or by holding CAP_CHOWN in the effective set.
func (c *chownChecker) check(_ context.Context) error {
	// Root can always chown.
	if c.getuid() == 0 {
		return nil
	}

	caps, err := c.capget()
	if err != nil {
		return fmt.Errorf("cannot read effective capabilities: %w", err)
	}

	if caps&(1<<unix.CAP_CHOWN) != 0 {
		return nil
	}

	return fmt.Errorf("process lacks CAP_CHOWN: extracted rootfs files will have incorrect ownership, " +
		"which may cause permission errors inside the guest; " +
		"grant CAP_CHOWN to the go-microvm process or run as root")
}

// getEffectiveCaps returns the low 32 bits of the effective capability set
// for the current process. This covers capabilities 0–31 which includes
// CAP_CHOWN (0).
func getEffectiveCaps() (uint32, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}

	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, fmt.Errorf("capget: %w", err)
	}

	return data[0].Effective, nil
}
