// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

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

func TestCache_BaseDir(t *testing.T) {
	t.Parallel()

	baseDir := "/some/cache/dir"
	c := NewCache(baseDir)

	assert.Equal(t, baseDir, c.BaseDir())

	var nilCache *Cache
	assert.Equal(t, "", nilCache.BaseDir())
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

func TestCache_Evict_RemovesOldEntries(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create a cache entry and backdate its mtime.
	oldDir := filepath.Join(cacheDir, "sha256-old")
	require.NoError(t, os.MkdirAll(oldDir, 0o700))
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(oldDir, oldTime, oldTime))

	// Create a fresh entry.
	newDir := filepath.Join(cacheDir, "sha256-new")
	require.NoError(t, os.MkdirAll(newDir, 0o700))

	removed, err := c.Evict(7 * 24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	// Old entry should be gone, new entry should remain.
	_, err = os.Stat(oldDir)
	assert.True(t, os.IsNotExist(err))

	_, err = os.Stat(newDir)
	assert.NoError(t, err)
}

func TestCache_Evict_CleansOldTmpDirs(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create a stale tmp directory (simulates interrupted extraction).
	tmpDir := filepath.Join(cacheDir, "tmp-rootfs-stale")
	require.NoError(t, os.MkdirAll(tmpDir, 0o700))
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(tmpDir, oldTime, oldTime))

	removed, err := c.Evict(7 * 24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	_, err = os.Stat(tmpDir)
	assert.True(t, os.IsNotExist(err))
}

func TestCache_Evict_PreservesFreshTmpDirs(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create a fresh tmp directory (simulates in-flight extraction).
	tmpDir := filepath.Join(cacheDir, "tmp-rootfs-fresh")
	require.NoError(t, os.MkdirAll(tmpDir, 0o700))

	removed, err := c.Evict(7 * 24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, removed)

	_, err = os.Stat(tmpDir)
	assert.NoError(t, err)
}

func TestCache_Evict_NonExistentDir(t *testing.T) {
	t.Parallel()

	c := NewCache(filepath.Join(t.TempDir(), "does-not-exist"))

	removed, err := c.Evict(7 * 24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 0, removed)
}

func TestCache_Get_TouchesMtime(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create a cache entry and backdate it.
	digest := "sha256:touchtest"
	entryDir := filepath.Join(cacheDir, "sha256-touchtest")
	require.NoError(t, os.MkdirAll(entryDir, 0o700))
	oldTime := time.Now().Add(-10 * 24 * time.Hour)
	require.NoError(t, os.Chtimes(entryDir, oldTime, oldTime))

	// Get should update the mtime.
	before := time.Now()
	path, ok := c.Get(digest)
	require.True(t, ok)
	assert.Equal(t, entryDir, path)

	info, err := os.Stat(entryDir)
	require.NoError(t, err)
	assert.True(t, info.ModTime().After(before) || info.ModTime().Equal(before),
		"Get should update mtime to prevent eviction")
}

// --- List tests ---

func TestCache_List_Empty(t *testing.T) {
	t.Parallel()

	c := NewCache(t.TempDir())

	entries, err := c.List()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestCache_List_NilCache(t *testing.T) {
	t.Parallel()

	var c *Cache
	entries, err := c.List()
	require.NoError(t, err)
	assert.Nil(t, entries)
}

func TestCache_List_WithEntries(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create two rootfs entries with files.
	for _, name := range []string{"sha256-aaa111", "sha256-bbb222"} {
		dir := filepath.Join(cacheDir, name)
		require.NoError(t, os.MkdirAll(dir, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("hello"), 0o644))
	}

	// Create a ref pointing to one of them (extended format).
	refsDir := filepath.Join(cacheDir, "refs")
	require.NoError(t, os.MkdirAll(refsDir, 0o700))
	refContent := "ghcr.io/org/image:latest\tsha256:aaa111\n"
	refHash := sha256.Sum256([]byte("ghcr.io/org/image:latest"))
	refFile := filepath.Join(refsDir, hex.EncodeToString(refHash[:]))
	require.NoError(t, os.WriteFile(refFile, []byte(refContent), 0o600))

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// Build a map for order-independent assertions.
	byDigest := make(map[string]CacheEntry)
	for _, e := range entries {
		byDigest[e.Digest] = e
	}

	withRefs, ok := byDigest["sha256:aaa111"]
	require.True(t, ok, "expected entry for sha256:aaa111")
	assert.Equal(t, []string{"ghcr.io/org/image:latest"}, withRefs.Refs)
	assert.Equal(t, int64(5), withRefs.Size) // "hello" is 5 bytes

	orphan, ok := byDigest["sha256:bbb222"]
	require.True(t, ok, "expected entry for sha256:bbb222")
	assert.Empty(t, orphan.Refs)
}

func TestCache_List_SkipsNonRootfs(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create entries that should be skipped.
	for _, name := range []string{"refs", "layers", "tmp-rootfs-abc"} {
		require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, name), 0o700))
	}

	// Create one real rootfs entry.
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "sha256-real"), 0o700))

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "sha256:real", entries[0].Digest)
}

func TestCache_List_LegacyRefFormat(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create a rootfs entry.
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "sha256-legacy"), 0o700))

	// Create a ref in legacy format (digest only, no imageRef).
	refsDir := filepath.Join(cacheDir, "refs")
	require.NoError(t, os.MkdirAll(refsDir, 0o700))
	refHash := sha256.Sum256([]byte("some-image:latest"))
	refFile := filepath.Join(refsDir, hex.EncodeToString(refHash[:]))
	require.NoError(t, os.WriteFile(refFile, []byte("sha256:legacy\n"), 0o600))

	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Legacy format: entry is referenced (not orphaned) but the original
	// image name is not recoverable, so a placeholder is used.
	assert.Equal(t, "sha256:legacy", entries[0].Digest)
	assert.Equal(t, []string{"(unknown image)"}, entries[0].Refs)
}

// --- GC tests ---

func TestCache_GC_NilCache(t *testing.T) {
	t.Parallel()

	var c *Cache
	removed, err := c.GC()
	require.NoError(t, err)
	assert.Equal(t, 0, removed)
}

func TestCache_GC_RemovesOrphans(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create two rootfs entries.
	liveDir := filepath.Join(cacheDir, "sha256-live")
	orphanDir := filepath.Join(cacheDir, "sha256-orphan")
	require.NoError(t, os.MkdirAll(liveDir, 0o700))
	require.NoError(t, os.MkdirAll(orphanDir, 0o700))

	// Create a ref pointing only to the live entry.
	refsDir := filepath.Join(cacheDir, "refs")
	require.NoError(t, os.MkdirAll(refsDir, 0o700))
	refHash := sha256.Sum256([]byte("my-image:latest"))
	refFile := filepath.Join(refsDir, hex.EncodeToString(refHash[:]))
	require.NoError(t, os.WriteFile(refFile, []byte("my-image:latest\tsha256:live\n"), 0o600))

	removed, err := c.GC()
	require.NoError(t, err)
	assert.Equal(t, 1, removed)

	// Live entry should remain.
	_, err = os.Stat(liveDir)
	assert.NoError(t, err)

	// Orphan should be gone.
	_, err = os.Stat(orphanDir)
	assert.True(t, os.IsNotExist(err))
}

func TestCache_GC_PreservesNonRootfs(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create non-rootfs entries that GC should not touch.
	refsDir := filepath.Join(cacheDir, "refs")
	layersDir := filepath.Join(cacheDir, "layers")
	tmpDir := filepath.Join(cacheDir, "tmp-rootfs-inflight")
	require.NoError(t, os.MkdirAll(refsDir, 0o700))
	require.NoError(t, os.MkdirAll(layersDir, 0o700))
	require.NoError(t, os.MkdirAll(tmpDir, 0o700))

	removed, err := c.GC()
	require.NoError(t, err)
	assert.Equal(t, 0, removed)

	// All should still exist.
	for _, d := range []string{refsDir, layersDir, tmpDir} {
		_, err := os.Stat(d)
		assert.NoError(t, err, "should not remove %s", d)
	}
}

func TestCache_GC_NoRefs(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create rootfs entries with no refs at all.
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "sha256-a"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "sha256-b"), 0o700))

	removed, err := c.GC()
	require.NoError(t, err)
	assert.Equal(t, 2, removed)
}

// --- Purge tests ---

func TestCache_Purge_NilCache(t *testing.T) {
	t.Parallel()

	var c *Cache
	err := c.Purge()
	require.NoError(t, err)
}

func TestCache_Purge_RemovesEverything(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Populate cache.
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "sha256-entry"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "refs"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "layers", "sha256-layer"), 0o700))

	err := c.Purge()
	require.NoError(t, err)

	_, err = os.Stat(cacheDir)
	assert.True(t, os.IsNotExist(err))
}

func TestCache_Purge_NonExistentDir(t *testing.T) {
	t.Parallel()

	c := NewCache(filepath.Join(t.TempDir(), "does-not-exist"))
	err := c.Purge()
	require.NoError(t, err)
}

// --- Ref format tests ---

func TestParseRefFile_ExtendedFormat(t *testing.T) {
	t.Parallel()

	data := []byte("ghcr.io/org/image:latest\tsha256:abc123\n")
	imageRef, digest := parseRefFile(data)
	assert.Equal(t, "ghcr.io/org/image:latest", imageRef)
	assert.Equal(t, "sha256:abc123", digest)
}

func TestParseRefFile_LegacyFormat(t *testing.T) {
	t.Parallel()

	data := []byte("sha256:abc123\n")
	imageRef, digest := parseRefFile(data)
	assert.Equal(t, "", imageRef)
	assert.Equal(t, "sha256:abc123", digest)
}

func TestParseRefFile_Empty(t *testing.T) {
	t.Parallel()

	imageRef, digest := parseRefFile([]byte(""))
	assert.Equal(t, "", imageRef)
	assert.Equal(t, "", digest)
}

func TestPutRef_ExtendedFormat(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	c.putRef("ghcr.io/org/image:v1", "sha256:deadbeef")

	// Read the file back and verify extended format.
	p := c.refPath("ghcr.io/org/image:v1")
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, "ghcr.io/org/image:v1\tsha256:deadbeef\n", string(data))

	// getRef should still work.
	digest, ok := c.getRef("ghcr.io/org/image:v1")
	assert.True(t, ok)
	assert.Equal(t, "sha256:deadbeef", digest)
}

func TestCache_GC_NonExistentDir(t *testing.T) {
	t.Parallel()

	c := NewCache(filepath.Join(t.TempDir(), "does-not-exist"))

	removed, err := c.GC()
	require.NoError(t, err)
	assert.Equal(t, 0, removed)
}

func TestCache_GC_MultipleRefsToSameDigest(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create one rootfs entry.
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "sha256-shared"), 0o700))

	// Create two refs pointing to the same digest.
	refsDir := filepath.Join(cacheDir, "refs")
	require.NoError(t, os.MkdirAll(refsDir, 0o700))
	for _, ref := range []string{"image:latest", "image:v1"} {
		h := sha256.Sum256([]byte(ref))
		p := filepath.Join(refsDir, hex.EncodeToString(h[:]))
		require.NoError(t, os.WriteFile(p, []byte(ref+"\tsha256:shared\n"), 0o600))
	}

	removed, err := c.GC()
	require.NoError(t, err)
	assert.Equal(t, 0, removed)

	// Entry should survive.
	_, err = os.Stat(filepath.Join(cacheDir, "sha256-shared"))
	assert.NoError(t, err)
}

func TestCache_GC_CorruptRefFiles(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Create a rootfs entry.
	require.NoError(t, os.MkdirAll(filepath.Join(cacheDir, "sha256-orphan"), 0o700))

	// Create refs dir with corrupt files (empty, whitespace-only).
	refsDir := filepath.Join(cacheDir, "refs")
	require.NoError(t, os.MkdirAll(refsDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(refsDir, "empty"), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(refsDir, "whitespace"), []byte("  \n"), 0o600))

	// Corrupt refs should not protect the orphaned entry.
	removed, err := c.GC()
	require.NoError(t, err)
	assert.Equal(t, 1, removed)
}

func TestLookupRef_UpgradesLegacyRef(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	digest := "sha256:legacyupgrade"
	imageRef := "ghcr.io/org/image:latest"

	// Create a rootfs entry with an OCI config.
	rootfsDir := filepath.Join(cacheDir, "sha256-legacyupgrade")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o700))
	require.NoError(t, os.WriteFile(
		filepath.Join(rootfsDir, ".oci-config.json"),
		[]byte(`{"Entrypoint":["/bin/sh"]}`), 0o600,
	))

	// Write a legacy-format ref file (digest only, no imageRef).
	refsDir := filepath.Join(cacheDir, "refs")
	require.NoError(t, os.MkdirAll(refsDir, 0o700))
	p := c.refPath(imageRef)
	require.NoError(t, os.WriteFile(p, []byte(digest+"\n"), 0o600))

	// LookupRef should succeed (legacy format is readable).
	result := c.LookupRef(imageRef)
	require.NotNil(t, result)
	assert.Equal(t, rootfsDir, result.Path)

	// After LookupRef, the ref file should be upgraded to extended format.
	data, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, imageRef+"\t"+digest+"\n", string(data),
		"LookupRef should upgrade legacy ref to extended format")

	// List should now show the real image name instead of (unknown image).
	entries, err := c.List()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, []string{imageRef}, entries[0].Refs)
}

func TestGetRef_BackwardCompatible(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	c := NewCache(cacheDir)

	// Write a legacy-format ref file manually.
	refsDir := filepath.Join(cacheDir, "refs")
	require.NoError(t, os.MkdirAll(refsDir, 0o700))
	p := c.refPath("old-image:latest")
	require.NoError(t, os.WriteFile(p, []byte("sha256:olddigest\n"), 0o600))

	// getRef should parse the legacy format.
	digest, ok := c.getRef("old-image:latest")
	assert.True(t, ok)
	assert.Equal(t, "sha256:olddigest", digest)
}
