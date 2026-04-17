// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsWhiteoutFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"whiteout file", ".wh.foo", true},
		{"opaque whiteout is also whiteout", ".wh..wh..opq", true},
		{"regular file", "regular.txt", false},
		{"no dot after wh", ".whnot", false},
		{"with directory prefix", "dir/.wh.bar", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, isWhiteoutFile(tt.input))
		})
	}
}

func TestIsOpaqueWhiteout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected bool
	}{
		{"opaque whiteout", ".wh..wh..opq", true},
		{"regular whiteout", ".wh.foo", false},
		{"with directory prefix", "dir/.wh..wh..opq", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, isOpaqueWhiteout(tt.input))
		})
	}
}

func TestApplyWhiteout(t *testing.T) {
	t.Parallel()

	t.Run("removes a regular file", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		targetFile := filepath.Join(root, "usr", "lib", "oldlib")
		require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0o755))
		require.NoError(t, os.WriteFile(targetFile, []byte("data"), 0o644))

		err := applyWhiteout(root, "usr/lib/.wh.oldlib")
		require.NoError(t, err)

		_, err = os.Stat(targetFile)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("removes a directory tree", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		targetDir := filepath.Join(root, "usr", "share", "oldpkg")
		require.NoError(t, os.MkdirAll(filepath.Join(targetDir, "subdir"), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(targetDir, "file.txt"), []byte("data"), 0o644))

		err := applyWhiteout(root, "usr/share/.wh.oldpkg")
		require.NoError(t, err)

		_, err = os.Stat(targetDir)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("no-op for nonexistent target", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		err := applyWhiteout(root, "usr/lib/.wh.nonexistent")
		require.NoError(t, err)
	})

	t.Run("rejects path traversal", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		err := applyWhiteout(root, "../../etc/.wh.passwd")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path traversal")
	})

	t.Run("refuses to walk through a symlink parent", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		// An attacker-planted layer substitutes etc with a symlink to a
		// host-owned directory. Before SafeWalk, a subsequent whiteout on
		// etc/.wh.passwd would RemoveAll through the symlink.
		outside := t.TempDir()
		victim := filepath.Join(outside, "passwd")
		require.NoError(t, os.WriteFile(victim, []byte("original"), 0o600))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "etc")))

		err := applyWhiteout(root, "etc/.wh.passwd")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")

		// The host-side file must be untouched.
		got, readErr := os.ReadFile(victim)
		require.NoError(t, readErr)
		assert.Equal(t, "original", string(got))
	})
}

func TestApplyOpaqueWhiteout(t *testing.T) {
	t.Parallel()

	t.Run("clears directory contents", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		dir := filepath.Join(root, "usr", "lib")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "a.so"), []byte("a"), 0o644))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "b.so"), []byte("b"), 0o644))
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "subdir"), 0o755))

		err := applyOpaqueWhiteout(root, "usr/lib")
		require.NoError(t, err)

		// Directory itself should still exist.
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.True(t, info.IsDir())

		// But it should be empty.
		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("nonexistent directory is no-op", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		err := applyOpaqueWhiteout(root, "nonexistent/dir")
		require.NoError(t, err)
	})

	t.Run("rejects path traversal", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()

		err := applyOpaqueWhiteout(root, "../../etc")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "escapes rootfs")
	})
}
