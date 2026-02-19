// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

// Get returns the path to a cached rootfs for the given digest, and true
// if it exists and appears valid. Returns ("", false) on a cache miss.
func (c *Cache) Get(digest string) (string, bool) {
	dir := c.pathFor(digest)

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", false
	}

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

// pathFor converts a digest like "sha256:abc123..." into a filesystem path
// inside the cache directory. The colon is replaced to avoid filesystem issues.
func (c *Cache) pathFor(digest string) string {
	// Replace "sha256:" prefix with "sha256-" for filesystem safety.
	safe := strings.ReplaceAll(digest, ":", "-")
	return filepath.Join(c.baseDir, safe)
}
