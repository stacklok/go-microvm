// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package boot

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stacklok/go-microvm/guest/vmconfig"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()

	assert.Equal(t, "/workspace", cfg.workspaceMountPoint)
	assert.Equal(t, "workspace", cfg.workspaceTag)
	assert.Equal(t, 1000, cfg.workspaceUID)
	assert.Equal(t, 1000, cfg.workspaceGID)
	assert.False(t, cfg.workspaceReadOnly)
	assert.Equal(t, "virtiofs", cfg.workspaceFSType)
	assert.Equal(t, 5, cfg.mountRetries)
	assert.Equal(t, 22, cfg.sshPort)
	assert.Equal(t, "/home/sandbox/.ssh/authorized_keys", cfg.sshKeysPath)
	assert.Equal(t, "/etc/sandbox-env", cfg.envFilePath)
	assert.Equal(t, "sandbox", cfg.userName)
	assert.Equal(t, "/home/sandbox", cfg.userHome)
	assert.Equal(t, "/bin/bash", cfg.userShell)
	assert.Equal(t, uint32(1000), cfg.userUID)
	assert.Equal(t, uint32(1000), cfg.userGID)
	assert.True(t, cfg.lockdownRoot)
}

func TestWithWorkspaceFSType(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithWorkspaceFSType("9p").apply(cfg)
	assert.Equal(t, "9p", cfg.workspaceFSType)
}

func TestWithHVSocketNetwork(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithHVSocketNetwork(2048).apply(cfg)
	assert.Equal(t, uint32(2048), cfg.hvSocketNetPort)
}

func TestApplyVMConfig(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	applyVMConfig(cfg, vmconfig.Config{
		TmpSizeMiB:      512,
		HVSocketNetPort: 2049,
		DisableSSH:      true,
		VirtioFSMounts: []vmconfig.VirtioFSMountInfo{
			{Tag: "workspace", FSType: "9p", ReadOnly: true},
		},
	})
	assert.Equal(t, uint32(512), cfg.tmpSizeMiB)
	assert.Equal(t, uint32(2049), cfg.hvSocketNetPort)
	assert.True(t, cfg.disableSSH)
	assert.Equal(t, "9p", cfg.workspaceFSType)
	assert.True(t, cfg.workspaceReadOnly)
}

func TestWithWorkspaceReadOnly(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	assert.False(t, cfg.workspaceReadOnly)

	WithWorkspaceReadOnly(true).apply(cfg)
	assert.True(t, cfg.workspaceReadOnly)

	WithWorkspaceReadOnly(false).apply(cfg)
	assert.False(t, cfg.workspaceReadOnly)
}

func TestWithWorkspace(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithWorkspace("/mnt/data", "data", 500, 500).apply(cfg)

	assert.Equal(t, "/mnt/data", cfg.workspaceMountPoint)
	assert.Equal(t, "data", cfg.workspaceTag)
	assert.Equal(t, 500, cfg.workspaceUID)
	assert.Equal(t, 500, cfg.workspaceGID)
}

func TestWithUser(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithUser("dev", "/home/dev", "/bin/zsh", 2000, 2000).apply(cfg)

	assert.Equal(t, "dev", cfg.userName)
	assert.Equal(t, "/home/dev", cfg.userHome)
	assert.Equal(t, "/bin/zsh", cfg.userShell)
	assert.Equal(t, uint32(2000), cfg.userUID)
	assert.Equal(t, uint32(2000), cfg.userGID)
}

func TestWithSSHPort(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithSSHPort(2222).apply(cfg)

	assert.Equal(t, 2222, cfg.sshPort)
}

func TestWithMountRetries(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithMountRetries(10).apply(cfg)

	assert.Equal(t, 10, cfg.mountRetries)
}

func TestWithSSHKeysPath(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithSSHKeysPath("/root/.ssh/authorized_keys").apply(cfg)

	assert.Equal(t, "/root/.ssh/authorized_keys", cfg.sshKeysPath)
}

func TestWithEnvFilePath(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithEnvFilePath("/etc/custom-env").apply(cfg)

	assert.Equal(t, "/etc/custom-env", cfg.envFilePath)
}

func TestWithLockdownRoot(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithLockdownRoot(false).apply(cfg)

	assert.False(t, cfg.lockdownRoot)
}

func TestWithoutSSH_SetsFlag(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	assert.False(t, cfg.disableSSH, "default boot config must leave SSH enabled")

	WithoutSSH().apply(cfg)
	assert.True(t, cfg.disableSSH)
}

func TestOptionComposition(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	opts := []Option{
		WithSSHPort(2222),
		WithUser("dev", "/home/dev", "/bin/zsh", 2000, 2000),
		WithLockdownRoot(false),
		WithMountRetries(3),
	}
	for _, o := range opts {
		o.apply(cfg)
	}

	// Last wins for scalars.
	assert.Equal(t, 2222, cfg.sshPort)
	assert.Equal(t, "dev", cfg.userName)
	assert.False(t, cfg.lockdownRoot)
	assert.Equal(t, 3, cfg.mountRetries)
	// Unchanged defaults.
	assert.Equal(t, "/workspace", cfg.workspaceMountPoint)
	assert.Equal(t, "/etc/sandbox-env", cfg.envFilePath)
}
