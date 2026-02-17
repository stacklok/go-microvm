// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mount

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEssentialRequiresRoot(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("test must run as non-root")
	}
	err := Essential(slog.Default())
	assert.Error(t, err)
}

func TestWorkspaceReturnsErrorForInvalidMount(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("test must run as non-root")
	}
	err := Workspace(slog.Default(), t.TempDir()+"/ws", "nonexistent-tag", 1000, 1000, 1)
	assert.Error(t, err)
}

func TestEssentialMountPoints(t *testing.T) {
	t.Parallel()

	// Verify the mount table contains the expected entries.
	expected := []string{"/proc", "/sys", "/dev", "/dev/pts", "/tmp", "/run"}
	mounts := []mountEntry{
		{"proc", "/proc", "proc", 0, ""},
		{"sysfs", "/sys", "sysfs", 0, ""},
		{"devtmpfs", "/dev", "devtmpfs", 0, ""},
		{"devpts", "/dev/pts", "devpts", 0, ""},
		{"tmpfs", "/tmp", "tmpfs", 0, "size=256m"},
		{"tmpfs", "/run", "tmpfs", 0, "size=64m"},
	}
	for i, m := range mounts {
		assert.Equal(t, expected[i], m.target)
	}
}
