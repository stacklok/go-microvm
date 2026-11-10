// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mount

import (
	"log/slog"
	"os"
	"syscall"
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
	err := Workspace(slog.Default(), t.TempDir()+"/ws", "nonexistent-tag", 1000, 1000, 1, false)
	assert.Error(t, err)
}

func TestWorkspaceMountEntry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		fstype   string
		readOnly bool
		wantData string
	}{
		{name: "virtiofs", fstype: "virtiofs"},
		{name: "read-only virtiofs", fstype: "virtiofs", readOnly: true},
		{name: "9p", fstype: "9p", wantData: "trans=virtio,version=9p2000.L,msize=524288"},
		{name: "read-only 9p", fstype: "9p", readOnly: true, wantData: "trans=virtio,version=9p2000.L,msize=524288,ro"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			entry := workspaceMountEntry("/workspace", "workspace", tt.fstype, tt.readOnly)
			assert.Equal(t, "workspace", entry.source)
			assert.Equal(t, "/workspace", entry.target)
			assert.Equal(t, tt.fstype, entry.fstype)
			assert.Equal(t, tt.wantData, entry.data)
			assert.Equal(t, tt.readOnly, entry.flags&syscall.MS_RDONLY != 0)
		})
	}

	t.Run("plan9 vsock trans=fd entry", func(t *testing.T) {
		t.Parallel()
		entry := plan9VsockMountEntry("/workspace", "workspace", 7, false)
		assert.Equal(t, "workspace", entry.source)
		assert.Equal(t, "/workspace", entry.target)
		assert.Equal(t, "9p", entry.fstype)
		assert.Equal(t, "trans=fd,rfdno=7,wfdno=7,msize=524288,version=9p2000.L,aname=workspace", entry.data)
		assert.Zero(t, entry.flags&syscall.MS_RDONLY)

		roEntry := plan9VsockMountEntry("/workspace", "workspace", 7, true)
		assert.Equal(t, "trans=fd,rfdno=7,wfdno=7,msize=524288,version=9p2000.L,aname=workspace,noload,ro", roEntry.data)
		assert.NotZero(t, roEntry.flags&syscall.MS_RDONLY)
	})
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
