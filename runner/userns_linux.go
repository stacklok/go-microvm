// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runner

import (
	"os/exec"
	"syscall"
)

// applyUserNamespace configures the exec.Cmd to spawn the child inside a
// new user namespace (CLONE_NEWUSER). The child process gains all
// capabilities within the namespace, which allows libkrun's virtiofs
// passthrough to use set_creds() for UID/GID switching.
//
// A single UID and GID mapping is created from the namespace ID to the
// host process's real UID/GID. The Go runtime handles writing uid_map,
// gid_map, and "deny" to setgroups (required before gid_map since
// Linux 3.19) via SysProcAttr.
//
// Note on libkrun's ScopedGid/ScopedUid Drop: When the RAII guard resets
// credentials back to UID/GID 0 via setresgid(-1, 0, -1), the call
// silently fails because GID 0 is unmapped. This is benign — the next
// set_creds call will set correct credentials, and root operations
// (GID 0) are skipped entirely by libkrun.
func applyUserNamespace(cmd *exec.Cmd, ns *UserNamespaceConfig) {
	if ns == nil {
		return
	}

	hostUID := uint32(syscall.Getuid())
	hostGID := uint32(syscall.Getgid())

	cmd.SysProcAttr.Cloneflags |= syscall.CLONE_NEWUSER
	cmd.SysProcAttr.UidMappings = []syscall.SysProcIDMap{
		{ContainerID: int(ns.UID), HostID: int(hostUID), Size: 1},
	}
	cmd.SysProcAttr.GidMappings = []syscall.SysProcIDMap{
		{ContainerID: int(ns.GID), HostID: int(hostGID), Size: 1},
	}
	// Deny setgroups inside the namespace. This is required by the kernel
	// before writing gid_map for unprivileged users (since Linux 3.19).
	// The Go runtime writes "deny" to /proc/<pid>/setgroups automatically
	// when GidMappingsEnableSetgroups is false (the zero value).
}
