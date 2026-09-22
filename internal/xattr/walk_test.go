// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"context"
	"fmt"
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
	link := filepath.Join(t.TempDir(), "link")
	require.NoError(t, os.Symlink(real, link))

	err := SetOverrideStatTree(link, 1000, 1000)
	assert.ErrorContains(t, err, "open authorized root")
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

func TestPrepareOwnershipBestEffortContinuesAfterEntryFailure(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "broken-dir")
	require.NoError(t, os.Mkdir(dir, 0o700))
	require.NoError(t, unix.Lsetxattr(dir, overrideKey, []byte("malformed"), 0))
	descendant := filepath.Join(dir, "descendant")
	sibling := filepath.Join(root, "sibling")
	require.NoError(t, os.WriteFile(descendant, nil, 0o600))
	require.NoError(t, os.WriteFile(sibling, nil, 0o640))

	report, err := PrepareOwnership(context.Background(), root, ".", 42, 43, false)
	require.NoError(t, err)
	require.False(t, report.Complete())
	assert.Contains(t, report.Error(), "malformed")
	assert.Equal(t, "42:43:0100600", readXattrOpt(t, descendant))
	assert.Equal(t, "42:43:0100640", readXattrOpt(t, sibling))
}

func TestPrepareOwnershipBestEffortBoundsFailures(t *testing.T) {
	root := t.TempDir()
	for i := range maxPreparationErrors + 3 {
		path := filepath.Join(root, fmt.Sprintf("broken-%02d", i))
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		require.NoError(t, unix.Lsetxattr(path, overrideKey, []byte("malformed"), 0))
	}
	report, err := PrepareOwnership(context.Background(), root, ".", 42, 43, false)
	require.NoError(t, err)
	assert.Len(t, report.Errors, maxPreparationErrors)
	assert.Equal(t, 3, report.Omitted)
	assert.Contains(t, report.Error(), "3 additional errors omitted")
}

func TestPrepareOwnershipBestEffortKeepsSymlinkConfined(t *testing.T) {
	root := t.TempDir()
	external := filepath.Join(t.TempDir(), "external")
	require.NoError(t, os.WriteFile(external, nil, 0o600))
	require.NoError(t, os.Symlink(external, filepath.Join(root, "link")))

	report, err := PrepareOwnership(context.Background(), root, ".", 42, 43, false)
	require.NoError(t, err)
	assert.True(t, report.Complete())
	assert.Empty(t, readXattrOpt(t, external))
}

func TestPrepareOwnershipBestEffortDoesNotSwallowCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := PrepareOwnership(ctx, t.TempDir(), ".", 42, 43, false)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestPrepareOwnershipInjectedFailures(t *testing.T) {
	t.Run("xattr read oversized", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		require.NoError(t, unix.Lsetxattr(path, overrideKey, make([]byte, 300), 0))
		file, err := os.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, file.Close()) })
		assert.ErrorContains(t, prepareEntry(int(file.Fd()), path, 1, 1, unix.S_IFREG|0o600), "read override_stat")
	})

	t.Run("xattr write strict", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(path, nil, 0o600))
		file, err := os.Open(path)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, file.Close()) })
		err = prepareEntryWith(int(file.Fd()), path, 1, 1, unix.S_IFREG|0o600, unix.Fgetxattr,
			func(int, string, []byte, int) error { return unix.EROFS })
		assert.ErrorContains(t, err, "write override_stat")
	})

	t.Run("directory enumeration strict", func(t *testing.T) {
		fd, err := unix.Open(t.TempDir(), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		report := PreparationReport{}
		err = prepareTreeWith(context.Background(), fd, ".", 1, 1, true, &report, unix.Openat,
			func(*os.File) ([]os.DirEntry, error) { return nil, unix.EACCES })
		assert.ErrorContains(t, err, "read directory")
	})

	t.Run("descendant open best effort continues sibling", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "blocked"), nil, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(root, "safe"), nil, 0o640))
		fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		require.NoError(t, err)
		report := PreparationReport{}
		err = prepareTreeWith(context.Background(), fd, ".", 1, 1, false, &report,
			func(parent int, name string, flags int, mode uint32) (int, error) {
				if name == "blocked" {
					return -1, unix.EACCES
				}
				return unix.Openat(parent, name, flags, mode)
			}, func(file *os.File) ([]os.DirEntry, error) { return file.ReadDir(-1) })
		require.NoError(t, err)
		assert.Contains(t, report.Error(), "blocked")
		assert.Equal(t, "1:1:0100640", readXattrOpt(t, filepath.Join(root, "safe")))
	})
}

func TestPrepareOwnershipPinnedTargetCannotEscapeAfterReplacement(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(target, "inside"), nil, 0o600))
	external := t.TempDir()
	externalFile := filepath.Join(external, "outside")
	require.NoError(t, os.WriteFile(externalFile, nil, 0o600))

	parts, err := validateTarget("target")
	require.NoError(t, err)
	fd, err := acquireTarget(root, "target", parts)
	require.NoError(t, err)
	oldTarget := filepath.Join(root, "old-target")
	require.NoError(t, os.Rename(target, oldTarget))
	require.NoError(t, os.Symlink(external, target))
	report := PreparationReport{}
	require.NoError(t, prepareTree(context.Background(), fd, "target", 42, 43, true, &report))
	assert.Contains(t, readXattrOpt(t, filepath.Join(oldTarget, "inside")), "42:43:")
	assert.Empty(t, readXattrOpt(t, externalFile))
}

func TestPrepareOwnershipDescendantReplacementCannotEscape(t *testing.T) {
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	replaced := filepath.Join(root, "replaced-victim")
	external := t.TempDir()
	externalFile := filepath.Join(external, "secret")
	require.NoError(t, os.Mkdir(victim, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(victim, "inside"), nil, 0o600))
	require.NoError(t, os.WriteFile(externalFile, nil, 0o600))
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	require.NoError(t, err)
	replacedOnce := false
	report := PreparationReport{}
	err = prepareTreeWith(context.Background(), fd, ".", 42, 43, false, &report,
		func(parent int, name string, flags int, mode uint32) (int, error) {
			if !replacedOnce && name == "victim" {
				replacedOnce = true
				require.NoError(t, os.Rename(victim, replaced))
				require.NoError(t, os.Symlink(external, victim))
			}
			return unix.Openat(parent, name, flags, mode)
		}, func(file *os.File) ([]os.DirEntry, error) { return file.ReadDir(-1) })
	require.NoError(t, err)
	assert.Empty(t, readXattrOpt(t, externalFile))
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
