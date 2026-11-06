// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"

	"github.com/stacklok/go-microvm/internal/pathutil"
)

// Cache provides content-addressable caching of extracted rootfs directories.
// Images are cached by their manifest digest, so re-pulling an unchanged image
// reuses the existing extraction.
type Cache struct {
	baseDir string
}

// NewCache creates a new cache rooted at baseDir. Missing directories are
// created lazily by writes or TempDir; reads may migrate an existing cache.
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

// LayerCache returns a parent-aware per-layer cache. Returns nil for a nil
// receiver. Each operation retries parent validation: bool methods miss on
// failure, error-returning methods report it. Retained handles therefore fail
// closed after a format/privacy failure and recover once it is repaired.
func (c *Cache) LayerCache() *LayerCache {
	if c == nil {
		return nil
	}
	return &LayerCache{baseDir: filepath.Join(c.baseDir, "layers"), parent: c}
}

// Get returns the path to a cached rootfs for the given digest, and true
// if it exists and appears valid. Returns ("", false) on a cache miss.
// On a hit, the entry's modification time is updated so that Evict does
// not remove frequently used entries.
func (c *Cache) Get(digest string) (string, bool) {
	if err := c.prepareRead(); err != nil {
		return "", false
	}
	dir := c.pathFor(digest)

	info, err := statCacheDir(dir)
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
	if err := c.ensureFormat(); err != nil {
		return fmt.Errorf("initialize cache: %w", err)
	}

	info, err := statCacheDir(rootfsPath)
	if err != nil {
		return fmt.Errorf("stat rootfs source: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("rootfs source is not a real directory: %s", rootfsPath)
	}
	dst := c.pathFor(digest)

	// If the destination already exists, another concurrent pull may have
	// beaten us. Validate duplicates using the same policy as Get.
	if info, err := statCacheDir(dst); err == nil {
		if !info.IsDir() {
			return fmt.Errorf("cached rootfs is not a real directory: %s", dst)
		}
		_ = os.RemoveAll(rootfsPath)
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat cached rootfs: %w", err)
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
	if err := c.ensureFormat(); err != nil {
		return "", fmt.Errorf("initialize cache: %w", err)
	}
	return os.MkdirTemp(c.baseDir, "tmp-rootfs-*")
}

// Evict removes old rootfs entries and owned extraction/migration temporaries.
// Metadata, arbitrary siblings and the layers container are retained. Maintenance
// (Evict, GC and Purge) requires quiescent callers, including other processes.
// Returns the number of entries removed.
func (c *Cache) Evict(maxAge time.Duration) (int, error) {
	if err := pathutil.ValidatePrivatePath(c.baseDir); err != nil {
		return 0, err
	}
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
		name := entry.Name()
		isTmp := strings.HasPrefix(name, "tmp-rootfs-") || strings.HasPrefix(name, "tmp-stale-") || strings.HasPrefix(name, "tmp-delete-")
		ownedDir := entry.IsDir() && (isRootfsEntry(name) || isTmp)
		ownedFile := entry.Type().IsRegular() && strings.HasPrefix(name, "tmp-format-")
		if !ownedDir && !ownedFile {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoff) {
			entryPath := filepath.Join(c.baseDir, name)
			remove := discardTree
			if isTmp {
				remove = removeTree
			}
			if err := remove(entryPath); err != nil {
				continue
			}
			removed++
		}
	}

	// Drop snapshots of layer prefixes no remaining entry starts with.
	snapRemoved, err := c.PruneSnapshots(maxAge)
	if err != nil {
		return removed, fmt.Errorf("prune snapshots: %w", err)
	}
	removed += snapRemoved

	// Maintenance must not migrate the parent or age the layers container.
	lc := NewLayerCache(filepath.Join(c.baseDir, "layers"))
	layerRemoved, err := lc.Evict(maxAge)
	if err != nil {
		return removed, fmt.Errorf("evict layer cache: %w", err)
	}
	removed += layerRemoved

	return removed, nil
}

// CacheEntry holds metadata about a single cached rootfs entry.
type CacheEntry struct {
	// Digest is the OCI manifest digest (e.g. "sha256:abc123...").
	Digest string
	// Path is the absolute filesystem path to the extracted rootfs.
	Path string
	// Size is the total size in bytes of all files in the rootfs directory.
	Size int64
	// ModTime is the modification time of the cache directory entry.
	// Updated by Get on cache hits; otherwise reflects creation time.
	ModTime time.Time
	// Refs lists image references (e.g. "ghcr.io/org/image:latest") that
	// point to this digest via the ref index. Empty for orphaned entries.
	Refs []string
}

// List returns metadata for all cached rootfs entries along with the image
// references that point to each digest. Orphaned entries (no refs) will
// have an empty Refs slice.
func (c *Cache) List() ([]CacheEntry, error) {
	if c == nil {
		return nil, nil
	}
	if err := pathutil.ValidatePrivatePath(c.baseDir); err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(c.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read cache dir: %w", err)
	}

	// Build reverse map: digest → []imageRef from the ref index.
	refMap := c.buildRefMap()

	var result []CacheEntry
	for _, entry := range entries {
		name := entry.Name()

		// Only consider real rootfs directories, not symlink entries.
		if !entry.IsDir() || !isRootfsEntry(name) {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		digest := dirNameToDigest(name)
		entryPath := filepath.Join(c.baseDir, name)
		size := dirSize(entryPath)

		result = append(result, CacheEntry{
			Digest:  digest,
			Path:    entryPath,
			Size:    size,
			ModTime: info.ModTime(),
			Refs:    refMap[digest],
		})
	}

	return result, nil
}

// GC removes rootfs entries not referenced by any ref index entry.
// Unlike [Evict] (which is time-based), GC is reachability-based: an entry
// survives if and only if at least one ref points to its digest.
// Returns the number of entries removed.
//
// GC is not safe for concurrent use with [Pull]. If another process is
// pulling an image while GC runs, the pulled entry may be collected before
// the ref index is updated. The consequence is a cache miss on the next
// run, not data corruption.
func (c *Cache) GC() (int, error) {
	if c == nil {
		return 0, nil
	}
	if err := pathutil.ValidatePrivatePath(c.baseDir); err != nil {
		return 0, err
	}

	entries, err := os.ReadDir(c.baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read cache dir: %w", err)
	}

	live, err := c.liveDigests()
	if err != nil {
		return 0, fmt.Errorf("enumerate live digests: %w", err)
	}

	removed := 0

	for _, entry := range entries {
		name := entry.Name()
		if !isRootfsEntry(name) {
			continue
		}

		digest := dirNameToDigest(name)
		if live[digest] {
			continue
		}

		entryPath := filepath.Join(c.baseDir, name)
		if err := discardTree(entryPath); err != nil {
			continue
		}
		removed++
	}

	// Snapshots are only taken at prefixes of cached rootfs entries, so the
	// ones no remaining entry starts with are unreachable too.
	if _, err := c.PruneSnapshots(0); err != nil {
		return removed, fmt.Errorf("prune snapshots: %w", err)
	}

	return removed, nil
}

// Purge removes the entire cache directory including all rootfs entries,
// the ref index, and the layer cache. Requires quiescent callers; do not unlink
// the stable migration lock while another process is using the cache.
func (c *Cache) Purge() error {
	if c == nil {
		return nil
	}
	if err := pathutil.ValidatePrivatePath(c.baseDir); err != nil {
		return err
	}
	if err := os.RemoveAll(c.baseDir); err != nil {
		return fmt.Errorf("remove cache dir: %w", err)
	}
	return nil
}

// liveDigests returns the set of digests referenced by at least one ref
// index entry. Returns a nil map and nil error when the refs directory
// does not exist (no images have been pulled yet). Returns a non-nil
// error if the refs directory exists but cannot be read, so callers
// can abort rather than treating all entries as orphaned.
func (c *Cache) liveDigests() (map[string]bool, error) {
	refsDir := filepath.Join(c.baseDir, refDir)
	entries, err := os.ReadDir(refsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read refs dir: %w", err)
	}

	live := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(refsDir, entry.Name()))
		if err != nil {
			continue
		}
		_, digest := parseRefFile(data)
		if digest != "" {
			live[digest] = true
		}
	}
	return live, nil
}

// buildRefMap returns a map from digest to the list of image references
// that point to it.
func (c *Cache) buildRefMap() map[string][]string {
	refsDir := filepath.Join(c.baseDir, refDir)
	entries, err := os.ReadDir(refsDir)
	if err != nil {
		return nil
	}

	refMap := make(map[string][]string)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(refsDir, entry.Name()))
		if err != nil {
			continue
		}
		imageRef, digest := parseRefFile(data)
		if digest == "" {
			continue
		}
		if imageRef != "" {
			refMap[digest] = append(refMap[digest], imageRef)
		} else if _, exists := refMap[digest]; !exists {
			// Legacy-format ref (digest only, no image name). Mark the
			// digest as referenced so it is not reported as orphaned.
			// The placeholder is replaced once the ref is upgraded to
			// extended format (e.g. on next LookupRef hit).
			refMap[digest] = []string{"(unknown image)"}
		}
	}
	return refMap
}

// parseRefFile parses the content of a ref index file. The file may contain
// either the legacy format (digest only) or the extended format
// (imageRef\tdigest). Returns the image reference (empty for legacy format)
// and the digest.
func parseRefFile(data []byte) (imageRef, digest string) {
	content := strings.TrimSpace(string(data))
	if content == "" {
		return "", ""
	}
	if idx := strings.IndexByte(content, '\t'); idx >= 0 {
		return content[:idx], content[idx+1:]
	}
	// Legacy format: digest only.
	return "", content
}

// isRootfsEntry returns true if the directory name looks like a cached
// rootfs entry (starts with "sha256-") rather than a special directory.
func isRootfsEntry(name string) bool {
	return strings.HasPrefix(name, "sha256-")
}

// dirNameToDigest converts a filesystem-safe directory name back to a digest.
// "sha256-abc123" → "sha256:abc123".
func dirNameToDigest(name string) string {
	return strings.Replace(name, "-", ":", 1)
}

// dirSize walks a directory tree and returns the total size of all regular
// files. Errors are silently ignored; the returned size is best-effort.
func dirSize(path string) int64 {
	var total int64
	_ = filepath.WalkDir(path, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
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
	return total
}

// pathFor converts a digest like "sha256:abc123..." into a filesystem path
// inside the cache directory. Only the first colon is replaced so the
// round-trip with [dirNameToDigest] is symmetric.
func (c *Cache) pathFor(digest string) string {
	if strings.ContainsAny(digest, "/\\") || strings.Contains(digest, "..") {
		// Defense-in-depth: reject digests that could escape the cache dir.
		// Normal OCI digests are "algorithm:hex" with no path separators.
		return filepath.Join(c.baseDir, "invalid-digest")
	}
	safe := strings.Replace(digest, ":", "-", 1)
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
// network or daemon I/O. Returns nil on any miss or error, including a cache
// written by an older format, whose entries are discarded.
func (c *Cache) LookupRef(imageRef string) *RootFS {
	if c == nil {
		return nil
	}
	if err := c.prepareRead(); err != nil {
		return nil
	}

	digest, ok := c.getRef(imageRef)
	if !ok {
		return nil
	}

	// Upgrade legacy-format ref files (digest only) to extended format
	// (imageRef\tdigest) so that List/GC can recover the image name.
	c.putRef(imageRef, digest)

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
	if err := pathutil.ValidatePrivatePath(c.baseDir); err != nil {
		return
	}
	c.putRef(imageRef, digest)
	c.putConfig(digest, cfg)
}

// getRef returns the cached digest for an image reference. It handles
// both the legacy format (digest only) and the extended format
// (imageRef\tdigest).
func (c *Cache) getRef(imageRef string) (string, bool) {
	p := c.refPath(imageRef)
	data, err := os.ReadFile(p)
	if err != nil {
		return "", false
	}
	_, digest := parseRefFile(data)
	if digest == "" {
		return "", false
	}
	return digest, true
}

// putRef stores the ref→digest mapping as a small file. The file uses the
// extended format "imageRef\tdigest\n" so that List/GC can recover the
// original image reference from the hashed filename.
func (c *Cache) putRef(imageRef, digest string) {
	dir := filepath.Join(c.baseDir, refDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	p := c.refPath(imageRef)
	_ = os.WriteFile(p, []byte(imageRef+"\t"+digest+"\n"), 0o600)
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
	info, err := statCacheDir(dir)
	if err != nil || !info.IsDir() {
		return
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(dir, configFile), data, 0o600)
}

// cacheFormat identifies what extraction stores in the cache. Bump it when
// extraction changes the content of cached rootfs or layer entries, so
// entries written by older versions are discarded instead of reused.
//
// Format 2 keeps setuid and setgid bits for unprivileged extraction.
const (
	cacheFormat     = "2"
	cacheFormatFile = "format"
	cacheFormatLock = ".format.lock"
)

// statCacheDir preserves directory-symlink compatibility unless extraction
// retains host special bits. Trim trailing separators, not other components:
// Lstat("link/") follows the link, while Clean could change symlink/.. semantics.
func statCacheDir(path string) (os.FileInfo, error) {
	if !pathutil.KeepsSpecialBits() {
		return os.Stat(path)
	}
	trimmed := strings.TrimRight(path, string(os.PathSeparator))
	if trimmed == "" && path != "" {
		trimmed = string(os.PathSeparator)
	}
	return os.Lstat(trimmed)
}

// existingCacheDir checks existence without creating storage. Validate before
// Stat so invalid paths still fail closed, including for error-returning reads.
func existingCacheDir(path string) error {
	if err := pathutil.ValidatePrivatePath(path); err != nil {
		return err
	}
	_, err := os.Stat(path)
	return err
}

// prepareRead leaves missing caches absent, but still migrates existing caches.
func (c *Cache) prepareRead() error {
	if err := existingCacheDir(c.baseDir); err != nil {
		return err
	}
	return c.ensureFormat()
}

// ensureFormat discards the cache's entries (unpacked rootfs, refs and
// extracted layers) when the cache was written in an older format, then
// records the current format. Pending tmp-* entries of concurrent pulls and
// files the caller keeps beside the cache, such as lock files, are left alone.
func (c *Cache) ensureFormat() error {
	if err := pathutil.EnsurePrivateDir(c.baseDir); err != nil {
		return fmt.Errorf("private cache boundary: %w", err)
	}
	if current, err := c.currentFormat(); err != nil || current {
		return err
	}

	// Serialize only migration/publication, never extraction. The lock inode
	// remains stable across migrations and eviction, including distinct Caches.
	lock := flock.New(filepath.Join(c.baseDir, cacheFormatLock))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	locked, err := lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return fmt.Errorf("lock cache format: %w", err)
	}
	if !locked {
		return fmt.Errorf("lock cache format: timed out")
	}
	defer lock.Unlock() //nolint:errcheck // best-effort unlock
	if current, err := c.currentFormat(); err != nil || current {
		return err
	}
	formatPath := filepath.Join(c.baseDir, cacheFormatFile)

	entries, err := os.ReadDir(c.baseDir)
	if err != nil {
		return fmt.Errorf("read cache dir: %w", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !isFormatEntry(name) {
			continue
		}
		// Move stale entries aside before deleting them. Migration does not
		// provide snapshot semantics for readers already using old entries.
		stale, err := os.MkdirTemp(c.baseDir, "tmp-stale-*")
		if err != nil {
			return fmt.Errorf("discard stale cache entry %s: %w", name, err)
		}
		if err := os.Rename(filepath.Join(c.baseDir, name), filepath.Join(stale, name)); err != nil {
			_ = os.Remove(stale)
			return fmt.Errorf("discard stale cache entry %s: %w", name, err)
		}
		if err := os.RemoveAll(stale); err != nil {
			return fmt.Errorf("discard stale cache entry %s: %w", name, err)
		}
	}

	tmp, err := os.CreateTemp(c.baseDir, "tmp-format-*")
	if err != nil {
		return fmt.Errorf("write cache format: %w", err)
	}
	_, werr := tmp.WriteString(cacheFormat)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), formatPath)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("write cache format: %w", werr)
	}
	return nil
}

// currentFormat only reads the marker; it never initializes or migrates.
func (c *Cache) currentFormat() (bool, error) {
	data, err := os.ReadFile(filepath.Join(c.baseDir, cacheFormatFile))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, fmt.Errorf("read cache format: %w", err)
	}
	return err == nil && string(data) == cacheFormat, nil
}

// isFormatEntry reports whether name is a cache entry whose content depends
// on the cache format.
func isFormatEntry(name string) bool {
	return isRootfsEntry(name) || name == refDir || name == "layers" ||
		name == snapshotDir || name == chainDir
}
