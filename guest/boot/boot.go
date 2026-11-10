// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package boot

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/stacklok/go-microvm/guest/env"
	"github.com/stacklok/go-microvm/guest/harden"
	"github.com/stacklok/go-microvm/guest/mount"
	"github.com/stacklok/go-microvm/guest/netcfg"
)

// Run executes the full guest boot sequence and returns a shutdown function.
// The caller should block on signals and then invoke shutdown before halting.
//
// Boot sequence:
//  1. Essential mounts (/proc, /sys, /dev, etc.)
//  2. Network configuration (eth0, default route, resolv.conf)
//  3. Workspace mount (non-fatal if fails)
//  4. Kernel sysctl hardening
//  5. Lock down /root (if enabled)
//  6. Fix home directory ownership (rootfs hooks may not chown on macOS)
//  7. Load environment file
//  8. Drop bounding capabilities + set no_new_privs
//  9. SSH bring-up (skipped when [WithoutSSH] is set or when built with -tags=nosshd)
//  10. Apply seccomp BPF filter (if enabled via [WithSeccomp])
//
// The SSH bring-up (parsing authorized_keys, loading the host key, starting
// the listener) lives in build-tag-gated files. By default the SSH path is
// compiled in — passing -tags=nosshd at build time strips it, removing
// golang.org/x/crypto/ssh from the dependency graph. Builds with that tag
// must call [WithoutSSH] to acknowledge that SSH is unavailable.
//
// When SSH is not brought up, the returned shutdown function is a no-op.
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
	var stopRelay func()
	if cfg.hvSocketNetPort > 0 {
		stopRelay, err = netcfg.StartHVSocketTAP(context.Background(), logger, cfg.hvSocketNetPort, "eth0")
		if err != nil {
			return nil, fmt.Errorf("starting Hyper-V socket network relay: %w", err)
		}
		defer func() {
			if err != nil {
				stopRelay()
			}
		}()
	}
	logger.Info("configuring network")
	if err := netcfg.Configure(logger); err != nil {
		if stopRelay != nil {
			stopRelay()
		}
		return nil, fmt.Errorf("network setup: %w", err)
	}

	// 3. Workspace mount (non-fatal — VM is still useful without it).
	logger.Info("mounting workspace")
	if err := mount.WorkspaceWithFSType(
		logger,
		cfg.workspaceMountPoint,
		cfg.workspaceTag,
		cfg.workspaceFSType,
		cfg.workspaceUID,
		cfg.workspaceGID,
		cfg.mountRetries,
		cfg.workspaceReadOnly,
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

	// 8. Drop unneeded capabilities from the bounding set.
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

	// 9. SSH bring-up. The real implementation lives in ssh_enabled.go
	// (//go:build sshd); the stub in ssh_disabled.go errors out if the
	// caller wanted SSH but the binary wasn't built with the tag.
	shutdown, err = bringUpSSH(logger, cfg, envVars)
	if err != nil {
		return nil, fmt.Errorf("ssh bring-up: %w", err)
	}

	// 10. Apply seccomp BPF filter (if enabled). This must be the last
	// step — all mounts, networking, and privileged operations are done.
	if cfg.seccomp {
		logger.Info("applying seccomp BPF filter")
		if err := harden.ApplySeccomp(); err != nil {
			return nil, fmt.Errorf("applying seccomp filter: %w", err)
		}
	}

	logger.Info("sandbox init ready")

	sshShutdown := shutdown
	return func() {
		sshShutdown()
		if stopRelay != nil {
			stopRelay()
		}
	}, nil
}

// lockdownRoot sets /root/ to mode 0700 so the sandbox user cannot read
// its contents.
func lockdownRoot(logger *slog.Logger) {
	logger.Info("locking down /root permissions")
	if err := os.Chmod("/root", 0o700); err != nil {
		logger.Warn("failed to chmod /root", "error", err)
	}
}
