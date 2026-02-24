// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package boot

// Option configures the boot sequence. Use the With* functions to create options.
type Option interface {
	apply(*config)
}

type optionFunc func(*config)

func (f optionFunc) apply(c *config) { f(c) }

// config holds all resolved boot configuration.
type config struct {
	workspaceMountPoint string
	workspaceTag        string
	workspaceUID        int
	workspaceGID        int
	mountRetries        int
	sshPort             int
	sshKeysPath         string
	sshHostKeyPath      string
	envFilePath         string
	userName            string
	userHome            string
	userShell           string
	userUID             uint32
	userGID             uint32
	lockdownRoot        bool
	sshAgentForwarding  bool
}

func defaultConfig() *config {
	return &config{
		workspaceMountPoint: "/workspace",
		workspaceTag:        "workspace",
		workspaceUID:        1000,
		workspaceGID:        1000,
		mountRetries:        5,
		sshPort:             22,
		sshKeysPath:         "/home/sandbox/.ssh/authorized_keys",
		sshHostKeyPath:      "/etc/ssh/ssh_host_ecdsa_key",
		envFilePath:         "/etc/sandbox-env",
		userName:            "sandbox",
		userHome:            "/home/sandbox",
		userShell:           "/bin/bash",
		userUID:             1000,
		userGID:             1000,
		lockdownRoot:        true,
	}
}

// WithWorkspace configures the virtiofs workspace mount.
func WithWorkspace(mountPoint, tag string, uid, gid int) Option {
	return optionFunc(func(c *config) {
		c.workspaceMountPoint = mountPoint
		c.workspaceTag = tag
		c.workspaceUID = uid
		c.workspaceGID = gid
	})
}

// WithMountRetries sets the maximum number of retries for workspace mount.
func WithMountRetries(n int) Option {
	return optionFunc(func(c *config) { c.mountRetries = n })
}

// WithSSHPort sets the port for the embedded SSH server.
func WithSSHPort(port int) Option {
	return optionFunc(func(c *config) { c.sshPort = port })
}

// WithSSHKeysPath sets the path to the authorized_keys file.
func WithSSHKeysPath(path string) Option {
	return optionFunc(func(c *config) { c.sshKeysPath = path })
}

// WithEnvFilePath sets the path to the environment file.
func WithEnvFilePath(path string) Option {
	return optionFunc(func(c *config) { c.envFilePath = path })
}

// WithUser configures the default user for SSH sessions.
func WithUser(name, home, shell string, uid, gid uint32) Option {
	return optionFunc(func(c *config) {
		c.userName = name
		c.userHome = home
		c.userShell = shell
		c.userUID = uid
		c.userGID = gid
	})
}

// WithLockdownRoot controls whether /root is locked to mode 0700.
func WithLockdownRoot(enabled bool) Option {
	return optionFunc(func(c *config) { c.lockdownRoot = enabled })
}

// WithSSHHostKeyPath sets the path to a PEM-encoded host private key
// injected into the guest rootfs. If the file exists at boot, the key
// is loaded into memory, the file is deleted, and the key is used as
// the SSH server's host key (enabling client-side pinning).
func WithSSHHostKeyPath(path string) Option {
	return optionFunc(func(c *config) { c.sshHostKeyPath = path })
}

// WithSSHAgentForwarding controls whether the SSH server supports
// agent forwarding. When enabled and the client requests it, the
// server creates a Unix socket and sets SSH_AUTH_SOCK for the session.
func WithSSHAgentForwarding(enabled bool) Option {
	return optionFunc(func(c *config) { c.sshAgentForwarding = enabled })
}
