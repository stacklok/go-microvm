// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// LayerCache provides content-addressable caching of individual OCI image layers.
// Layers are cached by their DiffID (uncompressed content hash from the image
// config), which is stable across registries and compression changes.
type LayerCache struct {
	baseDir string
}

// NewLayerCache creates a new layer cache rooted at baseDir. The directory is
// created lazily when the first entry is stored.
func NewLayerCache(baseDir string) *LayerCache {
	return &LayerCache{baseDir: baseDir}
}

// Has returns true if a cached layer exists for the given DiffID.
func (lc *LayerCache) Has(diffID v1.Hash) bool {
	_, ok := lc.Get(diffID)
	return ok
}

// Get returns the path to a cached layer for the given DiffID, and true
// if it exists and appears valid. Returns ("", false) on a cache miss.
// On a hit, the entry's modification time is updated so that Evict does
// not remove frequently used entries.
func (lc *LayerCache) Get(diffID v1.Hash) (string, bool) {
	dir := lc.pathFor(diffID)

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", false
	}

	// Touch mtime so Evict treats this as recently used.
	now := time.Now()
	_ = os.Chtimes(dir, now, now)

	return dir, true
}

// Put records that tempDir contains the extracted layer for diffID.
// It moves (renames) tempDir into the cache directory. After a
// successful Put, tempDir should no longer be used directly;
// callers should use the path returned by Get instead.
func (lc *LayerCache) Put(diffID v1.Hash, tempDir string) error {
	if err := os.MkdirAll(lc.baseDir, 0o700); err != nil {
		return fmt.Errorf("create layer cache dir: %w", err)
	}

	dst := lc.pathFor(diffID)

	// If the destination already exists, another concurrent extraction may
	// have beaten us. Remove the duplicate we just extracted.
	if _, err := os.Stat(dst); err == nil {
		_ = os.RemoveAll(tempDir)
		return nil
	}

	if err := os.Rename(tempDir, dst); err != nil {
		return fmt.Errorf("move layer to cache: %w", err)
	}

	return nil
}

// TempDir creates a temporary directory inside the cache's base directory.
// This ensures os.Rename in Put stays on the same filesystem, avoiding
// cross-device link errors (e.g. /tmp on tmpfs vs cache on a different mount).
func (lc *LayerCache) TempDir() (string, error) {
	if err := os.MkdirAll(lc.baseDir, 0o700); err != nil {
		return "", fmt.Errorf("create layer cache dir: %w", err)
	}
	return os.MkdirTemp(lc.baseDir, "tmp-layer-*")
}

// Evict removes cached entries whose modification time is older than maxAge.
// Stale temporary directories (tmp-*) from interrupted extractions are also
// cleaned if they are older than maxAge. Returns the number of entries removed.
func (lc *LayerCache) Evict(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(lc.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read layer cache dir: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			entryPath := filepath.Join(lc.baseDir, entry.Name())
			if err := os.RemoveAll(entryPath); err != nil {
				continue
			}
			removed++
		}
	}

	return removed, nil
}

// pathFor converts a DiffID into a filesystem path inside the cache directory.
func (lc *LayerCache) pathFor(diffID v1.Hash) string {
	safe := diffID.Algorithm + "-" + diffID.Hex
	return filepath.Join(lc.baseDir, safe)
}
