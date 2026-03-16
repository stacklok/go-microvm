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
	err := Essential(slog.Default(), 0)
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

func TestEssentialMounts(t *testing.T) {
	t.Parallel()

	t.Run("default targets", func(t *testing.T) {
		t.Parallel()
		mounts := EssentialMountsForTest(0)
		expected := []string{"/proc", "/sys", "/dev", "/dev/pts", "/tmp", "/run"}
		targets := make([]string, len(mounts))
		for i, m := range mounts {
			targets[i] = m.target
		}
		assert.Equal(t, expected, targets)
	})

	t.Run("zero uses default tmp size", func(t *testing.T) {
		t.Parallel()
		mounts := EssentialMountsForTest(0)
		// /tmp is the 5th entry.
		assert.Equal(t, "size=256m", mounts[4].data)
	})

	t.Run("custom tmp size flows through", func(t *testing.T) {
		t.Parallel()
		mounts := EssentialMountsForTest(512)
		assert.Equal(t, "size=512m", mounts[4].data)
	})
}
