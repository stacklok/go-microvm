// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runner

import (
	"os/exec"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyUserNamespace_Nil(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	applyUserNamespace(cmd, nil)

	// SysProcAttr should be unchanged.
	assert.Equal(t, syscall.CLONE_NEWUSER&cmd.SysProcAttr.Cloneflags, uintptr(0))
	assert.Nil(t, cmd.SysProcAttr.UidMappings)
	assert.Nil(t, cmd.SysProcAttr.GidMappings)
}

func TestApplyUserNamespace_SetsCloneflags(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	ns := &UserNamespaceConfig{UID: 1000, GID: 1000}
	applyUserNamespace(cmd, ns)

	assert.NotEqual(t, uintptr(0), cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWUSER,
		"CLONE_NEWUSER should be set")
	// Setsid should still be set.
	assert.True(t, cmd.SysProcAttr.Setsid)
}

func TestApplyUserNamespace_UIDMapping(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	ns := &UserNamespaceConfig{UID: 1000, GID: 1000}
	applyUserNamespace(cmd, ns)

	require.Len(t, cmd.SysProcAttr.UidMappings, 1)
	assert.Equal(t, 1000, cmd.SysProcAttr.UidMappings[0].ContainerID)
	assert.Equal(t, int(syscall.Getuid()), cmd.SysProcAttr.UidMappings[0].HostID)
	assert.Equal(t, 1, cmd.SysProcAttr.UidMappings[0].Size)
}

func TestApplyUserNamespace_GIDMapping(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	ns := &UserNamespaceConfig{UID: 1000, GID: 1000}
	applyUserNamespace(cmd, ns)

	require.Len(t, cmd.SysProcAttr.GidMappings, 1)
	assert.Equal(t, 1000, cmd.SysProcAttr.GidMappings[0].ContainerID)
	assert.Equal(t, int(syscall.Getgid()), cmd.SysProcAttr.GidMappings[0].HostID)
	assert.Equal(t, 1, cmd.SysProcAttr.GidMappings[0].Size)
}

func TestApplyUserNamespace_SetgroupsDenied(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	ns := &UserNamespaceConfig{UID: 1000, GID: 1000}
	applyUserNamespace(cmd, ns)

	// GidMappingsEnableSetgroups should be false (zero value), which causes
	// Go to write "deny" to /proc/<pid>/setgroups before writing gid_map.
	assert.False(t, cmd.SysProcAttr.GidMappingsEnableSetgroups)
}

func TestApplyUserNamespace_PreservesExistingCloneflags(t *testing.T) {
	t.Parallel()

	cmd := exec.Command("true")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:     true,
		Cloneflags: syscall.CLONE_NEWNS, // Pre-existing flag
	}

	ns := &UserNamespaceConfig{UID: 500, GID: 500}
	applyUserNamespace(cmd, ns)

	// Both CLONE_NEWNS and CLONE_NEWUSER should be set.
	assert.NotEqual(t, uintptr(0), cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWUSER)
	assert.NotEqual(t, uintptr(0), cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNS)
}
