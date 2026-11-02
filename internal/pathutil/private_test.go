// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrivatePath_Empty(t *testing.T) {
	cwd := t.TempDir()
	require.NoError(t, os.Chmod(cwd, 0o700))
	t.Chdir(cwd)
	require.Error(t, ValidatePrivatePath(""))
	require.Error(t, EnsurePrivateDir(""))
	require.Error(t, ensurePrivateDir(""))
	entries, err := os.ReadDir(cwd)
	require.NoError(t, err)
	require.Empty(t, entries)
}

// Exercise the boundary check on macOS too; production gates it on Linux nonroot.
func TestEnsurePrivateDir(t *testing.T) {
	t.Parallel()
	t.Run("raw parent components", func(t *testing.T) {
		for _, path := range []string{"..", "../cache", "cache/..", "cache/../new", "./cache//../new", "/tmp/cache/../new"} {
			require.Error(t, validatePrivatePath(path), path)
		}
		for _, path := range []string{".", "cache", "cache/./new", "cache/.../new", "cache/name.."} {
			require.NoError(t, validatePrivatePath(path), path)
		}
	})
	t.Run("trusted private ancestor", func(t *testing.T) {
		base := t.TempDir()
		child := filepath.Join(base, "public", "cache")
		require.NoError(t, os.MkdirAll(child, 0o755))
		require.NoError(t, ensurePrivateDir(child))
		info, err := os.Stat(filepath.Dir(child))
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), info.Mode().Perm())
	})
	t.Run("missing parents", func(t *testing.T) {
		base := t.TempDir()
		child := filepath.Join(base, "one", "two")
		require.NoError(t, ensurePrivateDir(child))
		for _, path := range []string{filepath.Dir(child), child} {
			info, err := os.Stat(path)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o700), info.Mode().Perm())
		}
	})
	t.Run("symlink resolution", func(t *testing.T) {
		base := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(base, "real", "sub"), 0o755))
		link := filepath.Join(base, "link")
		require.NoError(t, os.Symlink("real/sub", link))
		require.NoError(t, ensurePrivateDir(link))
		require.Error(t, ensurePrivateDir(link+"/../new"))
		require.NoDirExists(t, filepath.Join(base, "real", "new"))
		require.NoDirExists(t, filepath.Join(base, "new"))
		loop := filepath.Join(base, "loop")
		require.NoError(t, os.Symlink("loop", loop))
		require.Error(t, ensurePrivateDir(loop))
	})
	t.Run("unsafe unchanged and symlink escape", func(t *testing.T) {
		// Use the system temporary directory directly so no t.TempDir private
		// ancestor masks the deliberately unsafe container.
		outside, err := os.MkdirTemp("/tmp", "private-boundary-test-*")
		require.NoError(t, err)
		t.Cleanup(func() { _ = os.RemoveAll(outside) })
		require.NoError(t, os.Chmod(outside, 0o755))
		err = ensurePrivateDir(outside)
		require.ErrorContains(t, err, fmt.Sprintf("storage directory %q", outside))
		require.ErrorContains(t, err, fmt.Sprintf("owned by UID %d (0700)", os.Geteuid()))
		require.ErrorContains(t, err, "if this directory is yours and does not need shared access, set its permissions to 0700")
		require.ErrorContains(t, err, "otherwise choose a private storage location")
		info, err := os.Stat(outside)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o755), info.Mode().Perm())
		link := filepath.Join(t.TempDir(), "escape")
		require.NoError(t, os.Symlink(outside, link))
		err = ensurePrivateDir(link)
		require.ErrorContains(t, err, fmt.Sprintf("storage directory %q", link))
		require.NoError(t, os.Chmod(outside, 0o700))
		require.NoError(t, ensurePrivateDir(link))
		require.NoError(t, os.Chmod(outside, 0o777))
		require.Error(t, ensurePrivateDir(filepath.Join(outside, "new")))
		_, err = os.Stat(filepath.Join(outside, "new"))
		require.True(t, os.IsNotExist(err))
	})
}
