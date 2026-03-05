// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Cache provides content-addressable caching of extracted rootfs directories.
// Images are cached by their manifest digest, so re-pulling an unchanged image
// reuses the existing extraction.
type Cache struct {
	baseDir string
}

// NewCache creates a new cache rooted at baseDir. The directory is created
// lazily when the first entry is stored.
func NewCache(baseDir string) *Cache {
	return &Cache{baseDir: baseDir}
}

// BaseDir returns the root directory used for cached rootfs entries.
func (c *Cache) BaseDir() string {
	if c == nil {
		return ""
	}
	return c.baseDir
}

// LayerCache returns the per-layer cache, creating the layers/ subdirectory
// lazily. Returns nil if the receiver is nil.
func (c *Cache) LayerCache() *LayerCache {
	if c == nil {
		return nil
	}
	return NewLayerCache(filepath.Join(c.baseDir, "layers"))
}

// Get returns the path to a cached rootfs for the given digest, and true
// if it exists and appears valid. Returns ("", false) on a cache miss.
// On a hit, the entry's modification time is updated so that Evict does
// not remove frequently used entries.
func (c *Cache) Get(digest string) (string, bool) {
	dir := c.pathFor(digest)

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", false
	}

	// Touch mtime so Evict treats this as recently used.
	now := time.Now()
	_ = os.Chtimes(dir, now, now)

	return dir, true
}

// Has returns true if a cached rootfs exists for the given digest.
func (c *Cache) Has(digest string) bool {
	_, ok := c.Get(digest)
	return ok
}

// Put records that rootfsPath is the extracted rootfs for digest.
// It moves (renames) rootfsPath into the cache directory. After a
// successful Put, rootfsPath should no longer be used directly;
// callers should use the path returned by Get instead.
func (c *Cache) Put(digest string, rootfsPath string) error {
	if err := os.MkdirAll(c.baseDir, 0o700); err != nil {
		return fmt.Errorf("create cache dir: %w", err)
	}

	dst := c.pathFor(digest)

	// If the destination already exists, another concurrent pull may have
	// beaten us. Remove the duplicate we just extracted.
	if _, err := os.Stat(dst); err == nil {
		_ = os.RemoveAll(rootfsPath)
		return nil
	}

	if err := os.Rename(rootfsPath, dst); err != nil {
		return fmt.Errorf("move rootfs to cache: %w", err)
	}

	return nil
}

// TempDir creates a temporary directory inside the cache's base directory.
// This ensures os.Rename in Put stays on the same filesystem, avoiding
// cross-device link errors (e.g. /tmp on tmpfs vs cache on a different mount).
func (c *Cache) TempDir() (string, error) {
	if err := os.MkdirAll(c.baseDir, 0o700); err != nil {
		return "", fmt.Errorf("create cache dir: %w", err)
	}
	return os.MkdirTemp(c.baseDir, "tmp-rootfs-*")
}

// Evict removes cached entries whose modification time is older than maxAge.
// Stale temporary directories (tmp-*) from interrupted extractions are also
// cleaned if they are older than maxAge. Returns the number of entries removed.
func (c *Cache) Evict(maxAge time.Duration) (int, error) {
	entries, err := os.ReadDir(c.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read cache dir: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	removed := 0

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			entryPath := filepath.Join(c.baseDir, entry.Name())
			if err := os.RemoveAll(entryPath); err != nil {
				continue
			}
			removed++
		}
	}

	// Also evict from the per-layer cache.
	lc := c.LayerCache()
	layerRemoved, err := lc.Evict(maxAge)
	if err != nil {
		return removed, fmt.Errorf("evict layer cache: %w", err)
	}
	removed += layerRemoved

	return removed, nil
}

// pathFor converts a digest like "sha256:abc123..." into a filesystem path
// inside the cache directory. The colon is replaced to avoid filesystem issues.
func (c *Cache) pathFor(digest string) string {
	// Replace "sha256:" prefix with "sha256-" for filesystem safety.
	safe := strings.ReplaceAll(digest, ":", "-")
	return filepath.Join(c.baseDir, safe)
}

// --- Ref-based index ---
//
// The ref index maps image references (e.g. "ghcr.io/org/image:tag") to their
// manifest digest, allowing cache lookups without contacting a registry or
// daemon. This is critical for performance: the daemon fetcher (docker save)
// exports the entire image just to compute the digest.

const (
	refDir     = "refs"
	configFile = ".oci-config.json"
)

// LookupRef checks whether the cache has a valid entry for the given image
// reference. On a hit it returns a fully populated RootFS without any
// network or daemon I/O. Returns nil on any miss or error.
func (c *Cache) LookupRef(imageRef string) *RootFS {
	if c == nil {
		return nil
	}

	digest, ok := c.getRef(imageRef)
	if !ok {
		return nil
	}

	rootfsPath, ok := c.Get(digest)
	if !ok {
		return nil
	}

	cfg, err := c.getConfig(digest)
	if err != nil {
		return nil
	}

	return &RootFS{Path: rootfsPath, Config: cfg, FromCache: true}
}

// StoreRef records the ref→digest mapping and persists the OCI config
// alongside the cached rootfs entry. Both operations are best-effort.
func (c *Cache) StoreRef(imageRef, digest string, cfg *OCIConfig) {
	if c == nil {
		return
	}
	c.putRef(imageRef, digest)
	c.putConfig(digest, cfg)
}

// getRef returns the cached digest for an image reference.
func (c *Cache) getRef(imageRef string) (string, bool) {
	p := c.refPath(imageRef)
	data, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	digest := strings.TrimSpace(string(data))
	if digest == "" {
		return "", false
	}
	return digest, true
}

// putRef stores the ref→digest mapping as a small file.
func (c *Cache) putRef(imageRef, digest string) {
	dir := filepath.Join(c.baseDir, refDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	p := c.refPath(imageRef)
	_ = os.WriteFile(p, []byte(digest+"\n"), 0o600)
}

// refPath returns the filesystem path for a ref index entry. The image
// reference is hashed to avoid filesystem issues with slashes and colons.
func (c *Cache) refPath(imageRef string) string {
	h := sha256.Sum256([]byte(imageRef))
	return filepath.Join(c.baseDir, refDir, hex.EncodeToString(h[:]))
}

// getConfig reads the cached OCI config for a digest.
func (c *Cache) getConfig(digest string) (*OCIConfig, error) {
	p := filepath.Join(c.pathFor(digest), configFile)
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var cfg OCIConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// putConfig writes the OCI config as JSON inside the cache entry.
func (c *Cache) putConfig(digest string, cfg *OCIConfig) {
	if cfg == nil {
		return
	}
	dir := c.pathFor(digest)
	if _, err := os.Stat(dir); err != nil {
		return
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, configFile), data, 0o600)
}
