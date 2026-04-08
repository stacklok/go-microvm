// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSetOverrideStatTree_NestedTree(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	sub1 := filepath.Join(root, "a")
	sub2 := filepath.Join(root, "a", "b")
	require.NoError(t, os.MkdirAll(sub2, 0o755))

	// Create a regular file — it should also get the xattr.
	filePath := filepath.Join(sub1, "file.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("hi"), 0o644))

	require.NoError(t, SetOverrideStatTree(root, 1000, 1000))

	// All directories should have the xattr set.
	for _, dir := range []string{root, sub1, sub2} {
		val := readXattrOpt(t, dir)
		assert.Contains(t, val, "1000:1000:", "dir %s should have override xattr", dir)
	}

	// Regular files should also have the xattr set.
	val := readXattrOpt(t, filePath)
	assert.Contains(t, val, "1000:1000:", "file should have override xattr")
}

func TestSetOverrideStatTree_SymlinkToExternalDir(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	external := t.TempDir()
	externalSub := filepath.Join(external, "secret")
	require.NoError(t, os.Mkdir(externalSub, 0o755))

	// Create a symlink inside root pointing to an external directory.
	require.NoError(t, os.Symlink(external, filepath.Join(root, "escape")))

	require.NoError(t, SetOverrideStatTree(root, 1000, 1000))

	// The external directory must NOT have the xattr set.
	_, err := unix.Lgetxattr(external, overrideKey, make([]byte, 256))
	assert.Error(t, err, "external dir should not have override xattr")
	_, err = unix.Lgetxattr(externalSub, overrideKey, make([]byte, 256))
	assert.Error(t, err, "external subdir should not have override xattr")
}

func TestSetOverrideStatTree_SymlinkToFile(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	target := filepath.Join(root, "real.txt")
	require.NoError(t, os.WriteFile(target, []byte("data"), 0o644))
	require.NoError(t, os.Symlink(target, filepath.Join(root, "link.txt")))

	require.NoError(t, SetOverrideStatTree(root, 1000, 1000))

	// The real file gets the xattr (it's a regular file under root).
	val := readXattrOpt(t, target)
	assert.Contains(t, val, "1000:1000:", "real file should have override xattr")

	// The symlink itself should NOT have the xattr.
	link := filepath.Join(root, "link.txt")
	_, err := unix.Lgetxattr(link, overrideKey, make([]byte, 256))
	assert.Error(t, err, "symlink should not have override xattr")
}

func TestSetOverrideStatTree_InaccessibleRoot(t *testing.T) {
	t.Parallel()

	err := SetOverrideStatTree("/nonexistent/path/xattr-test", 1000, 1000)
	assert.Error(t, err, "should fail on inaccessible root")
}

func TestSetOverrideStatTree_EmptyDir(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	require.NoError(t, SetOverrideStatTree(root, 1000, 1000))

	// Root dir itself should have the xattr.
	val := readXattrOpt(t, root)
	assert.Contains(t, val, "1000:1000:", "root dir should have override xattr")
}

func TestSetOverrideStatTree_RootIsSymlink(t *testing.T) {
	t.Parallel()

	real := t.TempDir()
	sub := filepath.Join(real, "child")
	require.NoError(t, os.Mkdir(sub, 0o755))

	// Create a symlink that points to real. The walk should resolve it
	// and set xattrs on the real directory tree.
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(real, link))

	require.NoError(t, SetOverrideStatTree(link, 1000, 1000))

	val := readXattrOpt(t, real)
	assert.Contains(t, val, "1000:1000:", "resolved root should have override xattr")
	val = readXattrOpt(t, sub)
	assert.Contains(t, val, "1000:1000:", "child dir should have override xattr")
}

func TestSetOverrideStatTree_DifferentUIDGID(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	filePath := filepath.Join(root, "file.txt")
	require.NoError(t, os.WriteFile(filePath, []byte("data"), 0o644))

	// Use different UID and GID to verify both are written independently.
	require.NoError(t, SetOverrideStatTree(root, 1000, 2000))

	val := readXattrOpt(t, root)
	assert.Contains(t, val, "1000:2000:", "dir should have uid=1000 gid=2000")

	val = readXattrOpt(t, filePath)
	assert.Contains(t, val, "1000:2000:", "file should have uid=1000 gid=2000")
}

// readXattrOpt reads the override_stat xattr and returns its value, or
// empty string if the xattr is not set.
func readXattrOpt(t *testing.T, path string) string {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, overrideKey, buf)
	if err != nil {
		return ""
	}
	return string(buf[:n])
}
