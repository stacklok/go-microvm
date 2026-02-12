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

func TestNewCache(t *testing.T) {
	t.Parallel()

	baseDir := "/some/cache/dir"
	c := NewCache(baseDir)

	require.NotNil(t, c)
	assert.Equal(t, baseDir, c.baseDir)
}

func TestCache_Has_EmptyCache(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	c := NewCache(tmpDir)

	assert.False(t, c.Has("sha256:abc123"))
}

func TestCache_Get_UnknownDigest(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	c := NewCache(tmpDir)

	path, ok := c.Get("sha256:nonexistent")
	assert.False(t, ok)
	assert.Empty(t, path)
}

func TestCache_PutGet_RoundTrip(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create a temporary directory to simulate an extracted rootfs.
	rootfsDir := t.TempDir()
	markerFile := filepath.Join(rootfsDir, "marker.txt")
	err := os.WriteFile(markerFile, []byte("test content"), 0o644)
	require.NoError(t, err)

	digest := "sha256:deadbeef1234567890"

	// Put the rootfs into the cache.
	err = c.Put(digest, rootfsDir)
	require.NoError(t, err)

	// The original rootfsDir should have been renamed (moved).
	_, err = os.Stat(rootfsDir)
	assert.True(t, os.IsNotExist(err), "original rootfs dir should no longer exist after Put")

	// Get should return the cached path.
	cachedPath, ok := c.Get(digest)
	require.True(t, ok)
	assert.NotEmpty(t, cachedPath)

	// Verify the marker file is present in the cached directory.
	data, err := os.ReadFile(filepath.Join(cachedPath, "marker.txt"))
	require.NoError(t, err)
	assert.Equal(t, "test content", string(data))

	// Has should also return true now.
	assert.True(t, c.Has(digest))
}

func TestCache_Put_ColonDigestCreatesCorrectPath(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	rootfsDir := t.TempDir()

	digest := "sha256:abc123def456"
	err := c.Put(digest, rootfsDir)
	require.NoError(t, err)

	// The colon should be replaced with a dash in the filesystem path.
	expectedPath := filepath.Join(cacheDir, "sha256-abc123def456")
	info, err := os.Stat(expectedPath)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestCache_DoublePut_NoConcurrencyError(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	digest := "sha256:doubleput"

	// First put.
	rootfs1 := t.TempDir()
	err := os.WriteFile(filepath.Join(rootfs1, "first"), []byte("1"), 0o644)
	require.NoError(t, err)

	err = c.Put(digest, rootfs1)
	require.NoError(t, err)

	// Second put with a different rootfs dir should succeed without error.
	// The second rootfs should be cleaned up since the cache entry already exists.
	rootfs2 := t.TempDir()
	err = os.WriteFile(filepath.Join(rootfs2, "second"), []byte("2"), 0o644)
	require.NoError(t, err)

	err = c.Put(digest, rootfs2)
	require.NoError(t, err)

	// The second rootfs directory should have been removed.
	_, err = os.Stat(rootfs2)
	assert.True(t, os.IsNotExist(err), "second rootfs dir should be removed on duplicate Put")

	// The original cached content should still be intact.
	cachedPath, ok := c.Get(digest)
	require.True(t, ok)

	data, err := os.ReadFile(filepath.Join(cachedPath, "first"))
	require.NoError(t, err)
	assert.Equal(t, "1", string(data))
}
