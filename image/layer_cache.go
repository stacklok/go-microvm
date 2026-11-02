// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/stacklok/go-microvm/internal/pathutil"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// LayerCache provides content-addressable caching of individual OCI image layers.
// Layers are cached by their DiffID (uncompressed content hash from the image
// config), which is stable across registries and compression changes.
type LayerCache struct {
	baseDir string
	parent  *Cache
}

// NewLayerCache creates a new layer cache rooted at baseDir. Missing directories
// are created lazily by Put or TempDir. Standalone handles validate storage
// privacy but never infer a parent cache or migrate its format.
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
	if err := lc.prepareRead(); err != nil {
		return "", false
	}
	dir := lc.pathFor(diffID)

	info, err := statCacheDir(dir)
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
	if err := lc.prepare(); err != nil {
		return fmt.Errorf("initialize layer cache: %w", err)
	}

	info, err := statCacheDir(tempDir)
	if err != nil {
		return fmt.Errorf("stat layer source: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("layer source is not a real directory: %s", tempDir)
	}
	dst := lc.pathFor(diffID)

	// If the destination already exists, another concurrent extraction may
	// have beaten us. Validate duplicates using the same policy as Get.
	if info, err := statCacheDir(dst); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("cached layer is not a real directory: %s", dst)
		}
		_ = os.RemoveAll(tempDir)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat cached layer: %w", err)
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
	if err := lc.prepare(); err != nil {
		return "", fmt.Errorf("initialize layer cache: %w", err)
	}
	return os.MkdirTemp(lc.baseDir, "tmp-layer-*")
}

// Evict removes only old layer directories and tmp-layer-* extraction
// directories. Requires quiescent callers. It never migrates the parent cache.
// Returns the number of entries removed.
func (lc *LayerCache) Evict(maxAge time.Duration) (int, error) {
	if err := pathutil.ValidatePrivatePath(lc.baseDir); err != nil {
		return 0, err
	}
	if lc.parent != nil {
		if err := existingCacheDir(lc.parent.baseDir); err != nil {
			if os.IsNotExist(err) {
				return 0, nil
			}
			return 0, err
		}
		if err := pathutil.EnsurePrivateDir(lc.parent.baseDir); err != nil {
			return 0, err
		}
		current, err := lc.parent.currentFormat()
		if err != nil {
			return 0, err
		}
		if !current {
			return 0, fmt.Errorf("parent cache format requires initialization")
		}
	}
	entries, err := os.ReadDir(lc.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read layer cache dir: %w", err)
	}

	if err := pathutil.EnsurePrivateDir(lc.baseDir); err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for _, entry := range entries {
		if !entry.IsDir() || (!isRootfsEntry(entry.Name()) && !strings.HasPrefix(entry.Name(), "tmp-layer-")) {
			continue
		}
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

// Size returns the total size in bytes of all cached layer entries.
// Returns 0 if the layer cache directory does not exist.
func (lc *LayerCache) Size() (int64, error) {
	if lc == nil {
		return 0, nil
	}
	if err := lc.prepareRead(); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var total int64
	err := filepath.WalkDir(lc.baseDir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return fs.SkipAll
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		total += info.Size()
		return nil
	})
	if err != nil {
		return total, fmt.Errorf("walk layer cache: %w", err)
	}
	return total, nil
}

func (lc *LayerCache) prepareRead() error {
	if lc.parent != nil {
		if err := lc.parent.prepareRead(); err != nil {
			return fmt.Errorf("initialize parent cache: %w", err)
		}
	}
	if err := existingCacheDir(lc.baseDir); err != nil {
		return err
	}
	return pathutil.EnsurePrivateDir(lc.baseDir)
}

func (lc *LayerCache) prepare() error {
	if lc.parent != nil {
		if err := lc.parent.ensureFormat(); err != nil {
			return fmt.Errorf("initialize parent cache: %w", err)
		}
	}
	return pathutil.EnsurePrivateDir(lc.baseDir)
}

// pathFor converts a DiffID into a filesystem path inside the cache directory.
func (lc *LayerCache) pathFor(diffID v1.Hash) string {
	safe := diffID.Algorithm + "-" + diffID.Hex
	return filepath.Join(lc.baseDir, safe)
}
