// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package preflight

import (
	"context"
	"fmt"
	"os"
	"strings"
)

const usernsCloneSysctl = "/proc/sys/kernel/unprivileged_userns_clone"

// usernsChecker holds injectable dependencies for user namespace verification.
type usernsChecker struct {
	getuid   func() int
	readFile func(string) ([]byte, error)
}

func newUsernsChecker() *usernsChecker {
	return &usernsChecker{
		getuid:   os.Getuid,
		readFile: os.ReadFile,
	}
}

// check verifies that unprivileged user namespaces are available. Root
// can always create user namespaces, so the check only applies to
// non-root users. On kernels that don't expose the sysctl (e.g.
// Fedora 30+, most modern distros), the check passes — CLONE_NEWUSER
// is always available.
func (c *usernsChecker) check(_ context.Context) error {
	// Root can always create user namespaces.
	if c.getuid() == 0 {
		return nil
	}

	data, err := c.readFile(usernsCloneSysctl)
	if err != nil {
		if os.IsNotExist(err) {
			// Sysctl doesn't exist — unprivileged userns is always enabled.
			return nil
		}
		return fmt.Errorf("cannot read %s: %w", usernsCloneSysctl, err)
	}

	val := strings.TrimSpace(string(data))
	if val == "0" {
		return fmt.Errorf("unprivileged user namespaces are disabled (kernel.unprivileged_userns_clone=0); " +
			"the runner requires CLONE_NEWUSER for virtiofs UID/GID mapping; " +
			"enable with: sudo sysctl -w kernel.unprivileged_userns_clone=1")
	}

	return nil
}

// UserNamespaceCheck returns a preflight Check that verifies unprivileged
// user namespaces are available. This check should only be registered when
// user namespace spawning is configured.
func UserNamespaceCheck() Check {
	c := newUsernsChecker()
	return Check{
		Name:        "userns",
		Description: "Verify unprivileged user namespaces are available",
		Run:         c.check,
		Required:    true,
	}
}
