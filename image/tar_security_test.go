// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeWalk(t *testing.T) {
	t.Parallel()

	t.Run("root itself resolves", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		got, err := SafeWalk(root, ".")
		require.NoError(t, err)
		assert.Equal(t, filepath.Clean(root), got)
	})

	t.Run("normal path resolves", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "a", "b"), 0o755))
		got, err := SafeWalk(root, "a/b/file")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "a", "b", "file"), got)
	})

	t.Run("nonexistent leaf is allowed", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "a"), 0o755))
		got, err := SafeWalk(root, "a/missing")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "a", "missing"), got)
	})

	t.Run("leaf is a symlink — allowed, not inspected", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(root, "a"), 0o755))
		outside := t.TempDir()
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "a", "link")))
		got, err := SafeWalk(root, "a/link")
		require.NoError(t, err)
		assert.Equal(t, filepath.Join(root, "a", "link"), got)
	})

	t.Run("mid-path symlink is refused", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		outside := t.TempDir()
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "a")))
		_, err := SafeWalk(root, "a/b/file")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})

	t.Run("parent symlink is refused even when leaf exists through it", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		outside := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(outside, "existing"), 0o755))
		require.NoError(t, os.Symlink(outside, filepath.Join(root, "a")))
		_, err := SafeWalk(root, "a/existing")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "symlink")
	})

	t.Run("missing parent directory is refused", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		_, err := SafeWalk(root, "nonexistent/child")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing parent")
		assert.True(t, errors.Is(err, fs.ErrNotExist),
			"missing-parent error should unwrap to fs.ErrNotExist")
	})

	t.Run("non-directory parent is refused", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644))
		_, err := SafeWalk(root, "file/child")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-directory")
	})

	t.Run("path escapes root", func(t *testing.T) {
		t.Parallel()
		root := t.TempDir()
		_, err := SafeWalk(root, "../escape")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path traversal")
	})
}
