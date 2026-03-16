// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package boot

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"

	"golang.org/x/crypto/ssh"

	"github.com/stacklok/propolis/guest/env"
	"github.com/stacklok/propolis/guest/harden"
	"github.com/stacklok/propolis/guest/mount"
	"github.com/stacklok/propolis/guest/netcfg"
	"github.com/stacklok/propolis/guest/sshd"
)

// Run executes the full guest boot sequence and returns a shutdown function
// that stops the SSH server. The caller should block on signals and then
// invoke shutdown before halting.
//
// Boot sequence:
//  1. Essential mounts (/proc, /sys, /dev, etc.)
//  2. Network configuration (eth0, default route, resolv.conf)
//  3. Workspace mount (non-fatal if fails)
//  4. Kernel sysctl hardening
//  5. Lock down /root (if enabled)
//  6. Fix home directory ownership (rootfs hooks may not chown on macOS)
//  7. Load environment file
//  8. Parse SSH authorized keys
//  9. Drop bounding capabilities + set no_new_privs
//  10. Start SSH server
//  11. Apply seccomp BPF filter (if enabled via [WithSeccomp])
func Run(logger *slog.Logger, opts ...Option) (shutdown func(), err error) {
	cfg := defaultConfig()
	for _, o := range opts {
		o.apply(cfg)
	}

	// 1. Essential mounts — /proc is needed before netlink can work.
	logger.Info("mounting essential filesystems")
	if err := mount.Essential(logger, cfg.tmpSizeMiB); err != nil {
		return nil, fmt.Errorf("essential mounts: %w", err)
	}

	// 2. Network configuration.
	logger.Info("configuring network")
	if err := netcfg.Configure(logger); err != nil {
		return nil, fmt.Errorf("network setup: %w", err)
	}

	// 3. Workspace mount (non-fatal — VM is still useful without it).
	logger.Info("mounting workspace")
	if err := mount.Workspace(
		logger,
		cfg.workspaceMountPoint,
		cfg.workspaceTag,
		cfg.workspaceUID,
		cfg.workspaceGID,
		cfg.mountRetries,
	); err != nil {
		logger.Warn("workspace mount failed, continuing without workspace", "error", err)
	}

	// 4. Apply kernel sysctl hardening (needs /proc mounted).
	harden.KernelDefaults(logger)

	// 5. Lock down /root/ so the sandbox user cannot read it.
	if cfg.lockdownRoot {
		lockdownRoot(logger)
	}

	// 6. Fix home directory ownership. Rootfs hooks run on the host
	// before boot and may not be able to chown to the sandbox UID (e.g.
	// macOS non-root users). Fix ownership now that we're running as
	// root inside the guest.
	fixHomeOwnership(logger, cfg.userHome, int(cfg.userUID), int(cfg.userGID))

	// 7. Load environment file.
	envVars, err := env.Load(cfg.envFilePath)
	if err != nil {
		return nil, fmt.Errorf("loading environment: %w", err)
	}

	// 8. Parse authorized keys.
	authorizedKeys, err := ParseAuthorizedKeys(cfg.sshKeysPath)
	if err != nil {
		return nil, fmt.Errorf("parsing authorized keys: %w", err)
	}

	// 8b. Load injected host key (if present). The key is deleted from
	// disk after loading into memory so it cannot be read by the sandbox
	// user. If the file does not exist, hostKeySigner remains nil and the
	// SSH server will generate an ephemeral key.
	var hostKeySigner ssh.Signer
	if hostKeyPEM, readErr := os.ReadFile(cfg.sshHostKeyPath); readErr == nil {
		signer, parseErr := ssh.ParsePrivateKey(hostKeyPEM)
		if parseErr != nil {
			logger.Warn("failed to parse injected host key, falling back to ephemeral",
				"path", cfg.sshHostKeyPath, "error", parseErr)
		} else {
			hostKeySigner = signer
			logger.Info("loaded injected SSH host key", "path", cfg.sshHostKeyPath)
		}
		_ = os.Remove(cfg.sshHostKeyPath)
	}

	// 9. Drop unneeded capabilities from the bounding set.
	logger.Info("dropping unnecessary capabilities")
	if err := harden.DropBoundingCaps(
		harden.CapSetUID,
		harden.CapSetGID,
		harden.CapNetBindService,
	); err != nil {
		return nil, fmt.Errorf("dropping capabilities: %w", err)
	}

	logger.Info("setting no_new_privs")
	if err := harden.SetNoNewPrivs(); err != nil {
		return nil, fmt.Errorf("setting no_new_privs: %w", err)
	}

	// 10. Start SSH server.
	sshdCfg := sshd.Config{
		Port:            cfg.sshPort,
		AuthorizedKeys:  authorizedKeys,
		Env:             envVars,
		DefaultUID:      cfg.userUID,
		DefaultGID:      cfg.userGID,
		DefaultUser:     cfg.userName,
		DefaultHome:     cfg.userHome,
		DefaultShell:    cfg.userShell,
		DefaultWorkDir:  cfg.workspaceMountPoint,
		AgentForwarding: cfg.sshAgentForwarding,
		HostKey:         hostKeySigner,
		Logger:          logger,
	}
	srv, err := sshd.New(sshdCfg)
	if err != nil {
		return nil, fmt.Errorf("creating SSH server: %w", err)
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.sshPort))
	if err != nil {
		return nil, fmt.Errorf("listening on port %d: %w", cfg.sshPort, err)
	}

	go func() {
		if err := srv.Serve(ln); err != nil {
			logger.Error("SSH server error", "error", err)
		}
	}()

	// 11. Apply seccomp BPF filter (if enabled). This must be the last
	// step — all mounts, networking, and privileged operations are done.
	if cfg.seccomp {
		logger.Info("applying seccomp BPF filter")
		if err := harden.ApplySeccomp(); err != nil {
			return nil, fmt.Errorf("applying seccomp filter: %w", err)
		}
	}

	logger.Info("sandbox init ready", "ssh_port", cfg.sshPort)

	return func() { srv.Close() }, nil
}

// lockdownRoot sets /root/ to mode 0700 so the sandbox user cannot read
// its contents.
func lockdownRoot(logger *slog.Logger) {
	logger.Info("locking down /root permissions")
	if err := os.Chmod("/root", 0o700); err != nil {
		logger.Warn("failed to chmod /root", "error", err)
	}
}

// ParseAuthorizedKeys reads an authorized_keys file and returns the parsed
// public keys. Returns an error if no valid keys are found.
func ParseAuthorizedKeys(path string) ([]ssh.PublicKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var keys []ssh.PublicKey
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey(line)
		if err != nil {
			continue // skip unparseable lines
		}
		keys = append(keys, key)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in %s", path)
	}
	return keys, nil
}
