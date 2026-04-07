// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mount

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"time"
)

const defaultTmpSizeMiB = 256

type mountEntry struct {
	source string
	target string
	fstype string
	flags  uintptr
	data   string
}

// essentialMounts returns the mount table for Essential, applying the default
// tmp size when tmpSizeMiB is zero.
func essentialMounts(tmpSizeMiB uint32) []mountEntry {
	if tmpSizeMiB == 0 {
		tmpSizeMiB = defaultTmpSizeMiB
	}
	return []mountEntry{
		{"proc", "/proc", "proc", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, ""},
		{"sysfs", "/sys", "sysfs", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, ""},
		{"devtmpfs", "/dev", "devtmpfs", syscall.MS_NOSUID | syscall.MS_NOEXEC, ""},
		{"devpts", "/dev/pts", "devpts", syscall.MS_NOSUID | syscall.MS_NOEXEC, "newinstance,ptmxmode=0666,mode=0620,gid=5"},
		{"tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV, fmt.Sprintf("size=%dm", tmpSizeMiB)},
		{"tmpfs", "/run", "tmpfs", syscall.MS_NOSUID | syscall.MS_NODEV | syscall.MS_NOEXEC, "size=64m"},
	}
}

// Essential mounts the core filesystems required for a minimal Linux userspace.
// tmpSizeMiB sets the size of the /tmp tmpfs in MiB; 0 uses the default (256 MiB).
func Essential(logger *slog.Logger, tmpSizeMiB uint32) error {
	mounts := essentialMounts(tmpSizeMiB)

	for _, m := range mounts {
		if err := os.MkdirAll(m.target, 0o755); err != nil {
			return fmt.Errorf("creating mount point %s: %w", m.target, err)
		}

		if err := syscall.Mount(m.source, m.target, m.fstype, m.flags, m.data); err != nil {
			if errors.Is(err, syscall.EBUSY) {
				logger.Debug("filesystem already mounted", "target", m.target)
				continue
			}
			return fmt.Errorf("mounting %s on %s: %w", m.fstype, m.target, err)
		}
	}

	// Replace /dev/ptmx with a symlink to /dev/pts/ptmx. With the
	// newinstance devpts mount, the PTY multiplexer lives at
	// /dev/pts/ptmx, but glibc's posix_openpt() opens /dev/ptmx.
	// devtmpfs may auto-create /dev/ptmx as a device node, so remove
	// it first to ensure the symlink succeeds.
	_ = os.Remove("/dev/ptmx")
	if err := os.Symlink("/dev/pts/ptmx", "/dev/ptmx"); err != nil {
		return fmt.Errorf("creating /dev/ptmx symlink: %w", err)
	}

	// Create standard /dev symlinks.
	symlinks := [][2]string{
		{"/proc/self/fd", "/dev/fd"},
		{"/proc/self/fd/0", "/dev/stdin"},
		{"/proc/self/fd/1", "/dev/stdout"},
		{"/proc/self/fd/2", "/dev/stderr"},
	}

	for _, sl := range symlinks {
		if err := os.Symlink(sl[0], sl[1]); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("creating symlink %s: %w", sl[1], err)
		}
	}

	return nil
}

// Workspace mounts a virtiofs share at the given mount point, retrying up to
// maxRetries times to allow the host to expose the filesystem. On success the
// mount point is chowned to uid:gid. When readOnly is true the mount is
// performed with MS_RDONLY so the guest cannot write to it.
func Workspace(logger *slog.Logger, mountPoint, tag string, uid, gid, maxRetries int, readOnly bool) error {
	if err := os.MkdirAll(mountPoint, 0o755); err != nil {
		return fmt.Errorf("creating workspace mount point %s: %w", mountPoint, err)
	}

	flags := uintptr(syscall.MS_NOSUID | syscall.MS_NODEV)
	if readOnly {
		flags |= syscall.MS_RDONLY
	}

	var lastErr error
	for i := range maxRetries {
		lastErr = syscall.Mount(tag, mountPoint, "virtiofs", flags, "")
		if lastErr == nil {
			// Skip chown on read-only mounts: chown returns EROFS on a
			// filesystem mounted with MS_RDONLY. Ownership is cosmetic
			// anyway since the mount prevents writes regardless.
			if !readOnly {
				if err := os.Chown(mountPoint, uid, gid); err != nil {
					// Clean up the mount so we don't leave a mounted
					// filesystem that the caller thinks failed.
					_ = syscall.Unmount(mountPoint, 0)
					return fmt.Errorf("chown workspace %s: %w", mountPoint, err)
				}
			}
			return nil
		}
		logger.Warn("virtiofs mount failed, retrying",
			"tag", tag,
			"attempt", i+1,
			"max", maxRetries,
			"err", lastErr,
		)
		time.Sleep(500 * time.Millisecond)
	}

	return fmt.Errorf("mounting virtiofs tag %q on %s after %d retries: %w", tag, mountPoint, maxRetries, lastErr)
}
