// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testDiffID = v1.Hash{Algorithm: "sha256", Hex: "deadbeef1234567890abcdef"}

func TestLayerCache_Has_EmptyCache(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	lc := NewLayerCache(tmpDir)

	assert.False(t, lc.Has(testDiffID))
}

func TestLayerCache_Get_UnknownDiffID(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	lc := NewLayerCache(tmpDir)

	path, ok := lc.Get(testDiffID)
	assert.False(t, ok)
	assert.Empty(t, path)
}

func TestLayerCache_PutGet_RoundTrip(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)

	// Create a temporary directory to simulate an extracted layer.
	layerDir := t.TempDir()
	markerFile := filepath.Join(layerDir, "marker.txt")
	err := os.WriteFile(markerFile, []byte("layer content"), 0o644)
	require.NoError(t, err)

	// Put the layer into the cache.
	err = lc.Put(testDiffID, layerDir)
	require.NoError(t, err)

	// The original layerDir should have been renamed (moved).
	_, err = os.Stat(layerDir)
	assert.True(t, os.IsNotExist(err), "original layer dir should no longer exist after Put")

	// Get should return the cached path.
	cachedPath, ok := lc.Get(testDiffID)
	require.True(t, ok)
	assert.NotEmpty(t, cachedPath)

	// Verify the marker file is present in the cached directory.
	data, err := os.ReadFile(filepath.Join(cachedPath, "marker.txt"))
	require.NoError(t, err)
	assert.Equal(t, "layer content", string(data))

	// Has should also return true now.
	assert.True(t, lc.Has(testDiffID))
}

func TestLayerCache_DoublePut_NoConcurrencyError(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)

	// First put.
	layer1 := t.TempDir()
	err := os.WriteFile(filepath.Join(layer1, "first"), []byte("1"), 0o644)
	require.NoError(t, err)

	err = lc.Put(testDiffID, layer1)
	require.NoError(t, err)

	// Second put with a different dir should succeed without error.
	// The second dir should be cleaned up since the cache entry already exists.
	layer2 := t.TempDir()
	err = os.WriteFile(filepath.Join(layer2, "second"), []byte("2"), 0o644)
	require.NoError(t, err)

	err = lc.Put(testDiffID, layer2)
	require.NoError(t, err)

	// The second layer directory should have been removed.
	_, err = os.Stat(layer2)
	assert.True(t, os.IsNotExist(err), "second layer dir should be removed on duplicate Put")

	// The original cached content should still be intact.
	cachedPath, ok := lc.Get(testDiffID)
	require.True(t, ok)

	data, err := os.ReadFile(filepath.Join(cachedPath, "first"))
	require.NoError(t, err)
	assert.Equal(t, "1", string(data))
}

func TestLayerCache_TempDir_SameFilesystem(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)

	tmpDir, err := lc.TempDir()
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// The temp dir should be under the cache's base directory.
	assert.True(t, strings.HasPrefix(tmpDir, cacheDir),
		"temp dir %q should be under cache dir %q", tmpDir, cacheDir)
}

func TestLayerCache_Evict_RemovesOldEntries(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)

	// Create a cache entry and backdate its mtime.
	oldDir := filepath.Join(cacheDir, "sha256-old")
	require.NoError(t, os.MkdirAll(oldDir, 0o700))
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(oldDir, oldTime, oldTime))

	removed, err := lc.Evict(7 * 24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	// Old entry should be gone.
	_, err = os.Stat(oldDir)
	assert.True(t, os.IsNotExist(err))
}

func TestLayerCache_Evict_PreservesFreshEntries(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)

	// Create a fresh cache entry.
	freshDir := filepath.Join(cacheDir, "sha256-fresh")
	require.NoError(t, os.MkdirAll(freshDir, 0o700))

	removed, err := lc.Evict(7 * 24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, removed)

	// Fresh entry should still exist.
	_, err = os.Stat(freshDir)
	assert.NoError(t, err)
}

func TestLayerCache_Get_TouchesMtime(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)

	// Create a cache entry and backdate it.
	entryDir := lc.pathFor(testDiffID)
	require.NoError(t, os.MkdirAll(entryDir, 0o700))
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(entryDir, oldTime, oldTime))

	// Get should update the mtime.
	before := time.Now()
	path, ok := lc.Get(testDiffID)
	require.True(t, ok)
	assert.Equal(t, entryDir, path)

	info, err := os.Stat(entryDir)
	require.NoError(t, err)
	assert.True(t, info.ModTime().After(before) || info.ModTime().Equal(before),
		"Get should update mtime to prevent eviction")
}

func TestLayerCache_Evict_NonExistentDir(t *testing.T) {
	t.Parallel()

	lc := NewLayerCache(filepath.Join(t.TempDir(), "does-not-exist"))

	removed, err := lc.Evict(7 * 24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, removed)
}
