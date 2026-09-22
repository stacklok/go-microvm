// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package virtiofs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const overrideKey = "user.containers.override_stat"

func TestPrepareOwnershipTargeted(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	unrelated := filepath.Join(root, "unrelated")
	require.NoError(t, os.Mkdir(target, 0o750))
	require.NoError(t, os.Chmod(target, os.ModeSticky|0o750))
	require.NoError(t, os.WriteFile(filepath.Join(target, "file"), []byte("data"), 0o640))
	require.NoError(t, os.WriteFile(unrelated, []byte("other"), 0o600))

	before, err := os.Lstat(filepath.Join(target, "file"))
	require.NoError(t, err)
	beforeStat := before.Sys().(*syscall.Stat_t)

	require.NoError(t, PrepareOwnership(context.Background(), root, "target", 65532, 65532))
	assert.Equal(t, "65532:65532:041750", getOverride(t, target))
	assert.Equal(t, "65532:65532:0100640", getOverride(t, filepath.Join(target, "file")))
	assert.Empty(t, getOverride(t, root))
	assert.Empty(t, getOverride(t, unrelated))

	after, err := os.Lstat(filepath.Join(target, "file"))
	require.NoError(t, err)
	afterStat := after.Sys().(*syscall.Stat_t)
	assert.Equal(t, before.Mode(), after.Mode())
	assert.Equal(t, beforeStat.Uid, afterStat.Uid)
	assert.Equal(t, beforeStat.Gid, afterStat.Gid)
}

func TestPrepareOwnershipRejectsTargetsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	require.NoError(t, os.Symlink(external, filepath.Join(root, "link")))
	rootLink := filepath.Join(t.TempDir(), "root-link")
	require.NoError(t, os.Symlink(root, rootLink))

	for _, target := range []string{"", "/absolute", "../escape", "a/../escape", "a//b"} {
		err := PrepareOwnership(context.Background(), root, target, 1, 1)
		assert.Error(t, err, target)
	}
	for _, rootPath := range []string{rootLink, rootLink + string(os.PathSeparator), rootLink + string(os.PathSeparator) + "."} {
		assert.ErrorContains(t, PrepareOwnership(context.Background(), rootPath, ".", 1, 1), "authorized root")
	}
	trustedParent := t.TempDir()
	realRoot := filepath.Join(trustedParent, "root")
	require.NoError(t, os.Mkdir(realRoot, 0o700))
	ancestorLink := filepath.Join(t.TempDir(), "trusted-ancestor")
	require.NoError(t, os.Symlink(trustedParent, ancestorLink))
	require.NoError(t, PrepareOwnership(context.Background(), filepath.Join(ancestorLink, "root"), ".", 1, 1))
	assert.ErrorContains(t, PrepareOwnership(context.Background(), root, "link", 1, 1), "open target")
}

func TestPrepareOwnershipSkipsDescendantSymlink(t *testing.T) {
	root := t.TempDir()
	external := t.TempDir()
	externalFile := filepath.Join(external, "secret")
	require.NoError(t, os.WriteFile(externalFile, []byte("secret"), 0o600))
	require.NoError(t, os.Symlink(external, filepath.Join(root, "escape")))

	require.NoError(t, PrepareOwnership(context.Background(), root, ".", 42, 43))
	assert.Empty(t, getOverride(t, externalFile))
}

func TestPrepareOwnershipUnannotatedReadOnlyFileFailsWithoutXattrWritePermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires a non-root user to verify normal xattr permission enforcement")
	}

	// t.TempDir creates a caller-owned directory without inherited ACL assumptions.
	root := t.TempDir()
	path := filepath.Join(root, "readonly")
	require.NoError(t, os.WriteFile(path, []byte("data"), 0o600))
	require.NoError(t, os.Chmod(path, 0o400))
	before, err := os.Lstat(path)
	require.NoError(t, err)
	beforeStat := before.Sys().(*syscall.Stat_t)

	err = PrepareOwnership(context.Background(), root, "readonly", 42, 43)
	require.Error(t, err)
	assert.True(t, errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM), "expected a Unix permission error, got %v", err)
	assert.Empty(t, getOverride(t, path))

	after, err := os.Lstat(path)
	require.NoError(t, err)
	afterStat := after.Sys().(*syscall.Stat_t)
	assert.Equal(t, os.FileMode(0o400), after.Mode().Perm())
	assert.Equal(t, beforeStat.Uid, afterStat.Uid)
	assert.Equal(t, beforeStat.Gid, afterStat.Gid)
}

func TestPrepareOwnershipStrictErrors(t *testing.T) {
	t.Run("malformed existing value", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, unix.Lsetxattr(root, overrideKey, []byte("broken"), 0))
		assert.ErrorContains(t, PrepareOwnership(context.Background(), root, ".", 1, 1), "malformed")
	})

	t.Run("special file", func(t *testing.T) {
		if runtime.GOOS == "darwin" {
			t.Skip("mkfifo test is covered on Linux")
		}
		root := t.TempDir()
		require.NoError(t, unix.Mkfifo(filepath.Join(root, "pipe"), 0o600))
		assert.ErrorContains(t, PrepareOwnership(context.Background(), root, ".", 1, 1), "unsupported file type")
	})

	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		assert.ErrorIs(t, PrepareOwnership(ctx, t.TempDir(), ".", 1, 1), context.Canceled)
	})
}

func TestPrepareOwnershipPreservesGuestMode(t *testing.T) {
	tests := []struct {
		name     string
		dir      bool
		hostMode os.FileMode
		existing string
		uid      uint32
		gid      uint32
		want     string
	}{
		{name: "host 0644 guest 0600", hostMode: 0o644, existing: "7:8:0100600", uid: 7, gid: 8, want: "7:8:0100600"},
		{name: "changed owners", hostMode: 0o644, existing: "7:8:0100600", uid: 9, gid: 10, want: "9:10:0100600"},
		{name: "file type corrected", hostMode: 0o644, existing: "7:8:041750", uid: 7, gid: 8, want: "7:8:0101750"},
		{name: "directory sticky and set-ID preserved", dir: true, hostMode: 0o700, existing: "7:8:0106751", uid: 7, gid: 8, want: "7:8:046751"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "entry")
			if tt.dir {
				require.NoError(t, os.Mkdir(path, tt.hostMode))
			} else {
				require.NoError(t, os.WriteFile(path, nil, tt.hostMode))
			}
			require.NoError(t, unix.Lsetxattr(path, overrideKey, []byte(tt.existing), 0))
			require.NoError(t, PrepareOwnership(context.Background(), root, "entry", tt.uid, tt.gid))
			assert.Equal(t, tt.want, getOverride(t, path))
			info, err := os.Lstat(path)
			require.NoError(t, err)
			assert.Equal(t, tt.hostMode.Perm(), info.Mode().Perm())
		})
	}
}

func TestPrepareOwnershipMalformedMetadataIsNotClobbered(t *testing.T) {
	for _, value := range []string{
		"broken", "x:2:0100644", "1:x:0100644", "4294967296:2:0100644",
		"1:4294967296:0100644", "1:2:0100999", "1:2:0200000",
	} {
		t.Run(value, func(t *testing.T) {
			root := t.TempDir()
			require.NoError(t, unix.Lsetxattr(root, overrideKey, []byte(value), 0))
			assert.ErrorContains(t, PrepareOwnership(context.Background(), root, ".", 1, 2), "malformed")
			assert.Equal(t, value, getOverride(t, root))
		})
	}
}

func TestPrepareOwnershipMissingPaths(t *testing.T) {
	root := t.TempDir()
	assert.ErrorContains(t, PrepareOwnership(context.Background(), "", ".", 1, 1), "root must not be empty")
	assert.ErrorContains(t, PrepareOwnership(context.Background(), filepath.Join(root, "missing"), ".", 1, 1), "authorized root")
	assert.ErrorContains(t, PrepareOwnership(context.Background(), root, "missing", 1, 1), "open target")
}

func getOverride(t *testing.T, path string) string {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, overrideKey, buf)
	if isNoAttribute(err) {
		return ""
	}
	require.NoError(t, err)
	return string(buf[:n])
}
