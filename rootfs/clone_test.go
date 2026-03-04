// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package rootfs_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/rootfs"
)

func TestCloneDir(t *testing.T) {
	t.Parallel()

	t.Run("clones files and directories", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(src, "subdir"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(src, "hello.txt"), []byte("hello"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(src, "subdir", "nested.txt"), []byte("nested"), 0o644))

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		// Verify files exist and have correct content.
		got, err := os.ReadFile(filepath.Join(dst, "hello.txt"))
		require.NoError(t, err)
		assert.Equal(t, "hello", string(got))

		got, err = os.ReadFile(filepath.Join(dst, "subdir", "nested.txt"))
		require.NoError(t, err)
		assert.Equal(t, "nested", string(got))
	})

	t.Run("preserves file permissions", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(src, "exec.sh"), []byte("#!/bin/sh"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(src, "readonly.txt"), []byte("ro"), 0o444))

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		info, err := os.Stat(filepath.Join(dst, "exec.sh"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())

		info, err = os.Stat(filepath.Join(dst, "readonly.txt"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o444), info.Mode().Perm())
	})

	t.Run("recreates relative symlinks within boundary", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(src, "target.txt"), []byte("target"), 0o644))
		require.NoError(t, os.Symlink("target.txt", filepath.Join(src, "link.txt")))

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		// Verify symlink exists and points to the right target.
		linkTarget, err := os.Readlink(filepath.Join(dst, "link.txt"))
		require.NoError(t, err)
		assert.Equal(t, "target.txt", linkTarget)

		// Verify the symlink resolves correctly.
		got, err := os.ReadFile(filepath.Join(dst, "link.txt"))
		require.NoError(t, err)
		assert.Equal(t, "target", string(got))
	})

	t.Run("keeps absolute symlink within rootfs boundary", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		// Absolute symlink /etc/passwd in a rootfs means <rootfs>/etc/passwd,
		// which is within the clone boundary. This should be preserved.
		require.NoError(t, os.MkdirAll(filepath.Join(src, "etc"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(src, "etc", "passwd"), []byte("root:x:0:0"), 0o644))
		require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(src, "link-passwd")))

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		// The in-bounds absolute symlink should be recreated.
		linkTarget, err := os.Readlink(filepath.Join(dst, "link-passwd"))
		require.NoError(t, err)
		assert.Equal(t, "/etc/passwd", linkTarget)
	})

	t.Run("skips relative symlink escaping rootfs", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		// Relative symlink that traverses above the rootfs.
		require.NoError(t, os.Symlink("../../../../../../etc/passwd", filepath.Join(src, "escape.txt")))

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		// The escaping symlink should be skipped.
		_, err := os.Lstat(filepath.Join(dst, "escape.txt"))
		assert.True(t, os.IsNotExist(err), "escaping relative symlink should not be cloned")
	})

	t.Run("allows absolute symlink within rootfs", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(src, "usr", "lib"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(src, "usr", "lib", "libfoo.so.1"), []byte("lib"), 0o644))
		// Absolute symlink that stays within the rootfs (e.g., /usr/lib/libfoo.so -> /usr/lib/libfoo.so.1).
		require.NoError(t, os.Symlink("/usr/lib/libfoo.so.1", filepath.Join(src, "usr", "lib", "libfoo.so")))

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		// The in-bounds absolute symlink should be recreated.
		linkTarget, err := os.Readlink(filepath.Join(dst, "usr", "lib", "libfoo.so"))
		require.NoError(t, err)
		assert.Equal(t, "/usr/lib/libfoo.so.1", linkTarget)
	})

	t.Run("clones empty directory", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(src, "empty"), 0o755))

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		info, err := os.Stat(filepath.Join(dst, "empty"))
		require.NoError(t, err)
		assert.True(t, info.IsDir())
	})

	t.Run("errors on missing source", func(t *testing.T) {
		t.Parallel()

		dst := filepath.Join(t.TempDir(), "clone")
		err := rootfs.CloneDir("/nonexistent-path-that-does-not-exist", dst)
		assert.Error(t, err)
	})

	t.Run("restores read-only directory permissions", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		// Create a read-only subdirectory containing a file.
		restrictedDir := filepath.Join(src, "restricted")
		require.NoError(t, os.MkdirAll(restrictedDir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(restrictedDir, "secret.txt"), []byte("secret"), 0o600))
		// Make directory read-only after populating it.
		require.NoError(t, os.Chmod(restrictedDir, 0o555))
		t.Cleanup(func() {
			// Restore so t.TempDir() cleanup works.
			_ = os.Chmod(restrictedDir, 0o755)
		})

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		// File should be cloned despite restricted parent.
		got, err := os.ReadFile(filepath.Join(dst, "restricted", "secret.txt"))
		require.NoError(t, err)
		assert.Equal(t, "secret", string(got))

		// Directory permission should be restored to 0o555.
		info, err := os.Stat(filepath.Join(dst, "restricted"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o555), info.Mode().Perm())

		// Cleanup: make writable so t.TempDir() can remove.
		t.Cleanup(func() {
			_ = os.Chmod(filepath.Join(dst, "restricted"), 0o755)
		})
	})

	t.Run("handles nested directory symlinks", func(t *testing.T) {
		t.Parallel()

		src := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(src, "a"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(src, "a", "file.txt"), []byte("content"), 0o644))
		require.NoError(t, os.Symlink("a", filepath.Join(src, "b")))

		dst := filepath.Join(t.TempDir(), "clone")
		require.NoError(t, rootfs.CloneDir(src, dst))

		// The symlink should be recreated, not followed.
		linkTarget, err := os.Readlink(filepath.Join(dst, "b"))
		require.NoError(t, err)
		assert.Equal(t, "a", linkTarget)
	})

	t.Run("rejects source that is a symlink", func(t *testing.T) {
		t.Parallel()

		realDir := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(realDir, "file.txt"), []byte("data"), 0o644))

		linkDir := filepath.Join(t.TempDir(), "srclink")
		require.NoError(t, os.Symlink(realDir, linkDir))

		dst := filepath.Join(t.TempDir(), "clone")
		err := rootfs.CloneDir(linkDir, dst)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})
}
