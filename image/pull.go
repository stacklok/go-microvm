// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/stacklok/go-microvm/internal/xattr"
	"golang.org/x/sync/errgroup"
)

// maxExtractSize is a safety limit to prevent decompression bombs.
// 30 GB should be generous enough for any legitimate container image.
const maxExtractSize int64 = 30 << 30 // 30 GiB

// maxExtractEntries caps the number of tar entries accepted during
// extraction. Bounds inode exhaustion / tar-bomb variants where millions
// of small files fit easily under maxExtractSize but exhaust host inodes
// and the dentry cache. One million entries is far above the largest
// legitimate container images seen in practice (a few hundred thousand).
//
// Declared as var so tests can override it; no production caller should
// mutate it.
var maxExtractEntries = 1_000_000

// Pull fetches an OCI image, flattens its layers, and extracts to a directory.
// If a Cache is provided, results are cached by image digest. The returned
// RootFS contains the extraction path and parsed OCI config.
func Pull(ctx context.Context, imageRef string, cache *Cache) (*RootFS, error) {
	return PullWithFetcher(ctx, imageRef, cache, nil)
}

// PullWithFetcher is like Pull but uses the provided ImageFetcher.
// If fetcher is nil, the default local-then-remote fallback fetcher is used,
// which tries the local Docker/Podman daemon first before falling back to
// remote registry pull.
func PullWithFetcher(ctx context.Context, imageRef string, cache *Cache, fetcher ImageFetcher) (*RootFS, error) {
	tracer := otel.Tracer("github.com/stacklok/go-microvm")

	if fetcher == nil {
		fetcher = NewLocalThenRemoteFetcher()
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", imageRef, err)
	}

	// Fast path: check if we have a cached ref→digest mapping with a valid
	// rootfs entry. This avoids the daemon/registry fetch entirely — critical
	// because daemon.Image() does a full "docker save" export.
	if cached := cache.LookupRef(ref.String()); cached != nil {
		slog.Debug("using ref-indexed cache hit", "ref", ref.String(), "path", cached.Path)
		_, span := tracer.Start(ctx, "microvm.image.CacheLookup",
			trace.WithAttributes(attribute.Bool("microvm.image.cache_hit", true)))
		span.End()
		return cached, nil
	}

	slog.Debug("pulling image", "ref", ref.String())

	// Fetch image from daemon or registry.
	_, fetchSpan := tracer.Start(ctx, "microvm.image.Fetch")
	img, err := fetcher.Pull(ctx, ref.String())
	if err != nil {
		fetchSpan.RecordError(err)
		fetchSpan.SetStatus(codes.Error, err.Error())
		fetchSpan.End()
		return nil, fmt.Errorf("pull image %q: %w", imageRef, err)
	}
	fetchSpan.End()

	// Compute the manifest digest for cache keying.
	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute image digest: %w", err)
	}

	digestStr := digest.String()
	slog.Debug("image digest", "digest", digestStr)

	// Check cache before extracting (covers the case where the ref index
	// missed but the digest entry exists, e.g. pulled under a different tag).
	if cache != nil {
		if cachedPath, ok := cache.Get(digestStr); ok {
			slog.Debug("using cached rootfs", "path", cachedPath)
			_, span := tracer.Start(ctx, "microvm.image.CacheLookup",
				trace.WithAttributes(attribute.Bool("microvm.image.cache_hit", true)))
			span.End()
			ociCfg, err := extractOCIConfig(img)
			if err != nil {
				return nil, fmt.Errorf("extract OCI config: %w", err)
			}
			cache.StoreRef(ref.String(), digestStr, ociCfg)
			return &RootFS{Path: cachedPath, Config: ociCfg, FromCache: true}, nil
		}
	}

	// Extract OCI config.
	ociCfg, err := extractOCIConfig(img)
	if err != nil {
		return nil, fmt.Errorf("extract OCI config: %w", err)
	}

	// Create a temporary directory for extraction. When a cache is
	// available, create it inside the cache directory so that the
	// subsequent os.Rename stays on the same filesystem.
	var tmpDir string
	if cache != nil {
		tmpDir, err = cache.TempDir()
	} else {
		tmpDir, err = os.MkdirTemp("", "go-microvm-rootfs-*")
	}
	if err != nil {
		return nil, fmt.Errorf("create temp dir for rootfs: %w", err)
	}

	// Extract the filesystem. When a cache is available, use layered
	// extraction to benefit from per-layer caching. Falls back to flat
	// extraction if layered extraction fails.
	_, extractSpan := tracer.Start(ctx, "microvm.image.Extract")
	if cache != nil {
		lc := cache.LayerCache()
		extractSpan.SetAttributes(attribute.Bool("microvm.image.layered", true))
		if err := extractImageLayered(ctx, img, tmpDir, lc); err != nil {
			slog.Warn("layered extraction failed, falling back to flat extraction", "err", err)
			extractSpan.SetAttributes(attribute.Bool("microvm.image.layered", false))
			// Clean tmpDir contents before retrying with flat extraction.
			_ = os.RemoveAll(tmpDir)
			if tmpDir, err = cache.TempDir(); err != nil {
				extractSpan.RecordError(err)
				extractSpan.SetStatus(codes.Error, err.Error())
				extractSpan.End()
				return nil, fmt.Errorf("create temp dir for rootfs: %w", err)
			}
			if err := extractImage(ctx, img, tmpDir); err != nil {
				_ = os.RemoveAll(tmpDir)
				extractSpan.RecordError(err)
				extractSpan.SetStatus(codes.Error, err.Error())
				extractSpan.End()
				return nil, fmt.Errorf("extract image layers: %w", err)
			}
		}
	} else {
		extractSpan.SetAttributes(attribute.Bool("microvm.image.layered", false))
		if err := extractImage(ctx, img, tmpDir); err != nil {
			_ = os.RemoveAll(tmpDir)
			extractSpan.RecordError(err)
			extractSpan.SetStatus(codes.Error, err.Error())
			extractSpan.End()
			return nil, fmt.Errorf("extract image layers: %w", err)
		}
	}
	extractSpan.End()

	// Ensure the rootfs root directory itself is world-accessible and has
	// the override_stat xattr. The root dir is created by os.MkdirTemp
	// (mode 0700) and no tar entry covers it, so without this fix the
	// guest's uid 1000 user cannot traverse /.
	if err := os.Chmod(tmpDir, 0o755); err != nil {
		slog.Warn("chmod rootfs root dir failed", "err", err)
	}
	xattr.SetOverrideStat(tmpDir, 0, 0, os.ModeDir|0o755)

	// Move into cache if available. The extraction is fresh and this is
	// the only reference, so FromCache stays false — callers may safely
	// modify the rootfs in place without a COW clone.
	rootfsPath := tmpDir
	if cache != nil {
		_, cacheSpan := tracer.Start(ctx, "microvm.image.CacheStore")
		if err := cache.Put(digestStr, tmpDir); err != nil {
			_ = os.RemoveAll(tmpDir)
			cacheSpan.RecordError(err)
			cacheSpan.SetStatus(codes.Error, err.Error())
			cacheSpan.End()
			return nil, fmt.Errorf("cache rootfs: %w", err)
		}
		// After Put, the canonical path is in the cache.
		if cachedPath, ok := cache.Get(digestStr); ok {
			rootfsPath = cachedPath
		}
		// Record ref→digest mapping and OCI config for next-run fast path.
		cache.StoreRef(ref.String(), digestStr, ociCfg)
		cacheSpan.End()
	}

	return &RootFS{Path: rootfsPath, Config: ociCfg}, nil
}

// extractOCIConfig parses the image configuration into our OCIConfig type.
func extractOCIConfig(img v1.Image) (*OCIConfig, error) {
	cfgFile, err := img.ConfigFile()
	if err != nil {
		return nil, fmt.Errorf("read image config: %w", err)
	}

	if cfgFile == nil {
		return &OCIConfig{}, nil
	}

	cfg := cfgFile.Config
	return &OCIConfig{
		Entrypoint: cfg.Entrypoint,
		Cmd:        cfg.Cmd,
		Env:        cfg.Env,
		WorkingDir: cfg.WorkingDir,
		User:       cfg.User,
	}, nil
}

// contextReader wraps an io.Reader with context cancellation support.
// It checks the context before each Read call, enabling cancellation of
// long-running I/O operations (e.g. slow registry downloads).
type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (cr *contextReader) Read(p []byte) (int, error) {
	if err := cr.ctx.Err(); err != nil {
		return 0, err
	}
	return cr.r.Read(p)
}

// extractImage flattens all image layers into a single tar stream and extracts
// it to the destination directory. It includes security measures against path
// traversal, symlink attacks, and decompression bombs.
func extractImage(ctx context.Context, img v1.Image, dst string) error {
	reader := mutate.Extract(img)
	defer func() { _ = reader.Close() }()

	return extractTar(ctx, &contextReader{ctx: ctx, r: reader}, dst)
}

// extractImageLayered extracts each image layer individually into the layer
// cache, then composes them bottom-to-top into dst. Shared layers across
// images are extracted only once.
func extractImageLayered(ctx context.Context, img v1.Image, dst string, lc *LayerCache) error {
	layers, err := img.Layers()
	if err != nil {
		return fmt.Errorf("get image layers: %w", err)
	}

	cfgFile, err := img.ConfigFile()
	if err != nil {
		return fmt.Errorf("get image config: %w", err)
	}

	diffIDs := cfgFile.RootFS.DiffIDs
	if len(layers) != len(diffIDs) {
		return fmt.Errorf("layer count mismatch: %d layers vs %d diffIDs", len(layers), len(diffIDs))
	}

	// Extract uncached layers in parallel with bounded concurrency.
	concurrency := runtime.NumCPU()
	if concurrency > 4 {
		concurrency = 4
	}

	// Shared size budget across all layers to prevent decompression bombs.
	// Each layer's extraction decrements from this shared counter.
	remaining := &atomic.Int64{}
	remaining.Store(maxExtractSize)

	g, gCtx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)

	for i, layer := range layers {
		diffID := diffIDs[i]

		if lc.Has(diffID) {
			slog.Debug("layer cache hit", "diffID", diffID.String(), "index", i)
			continue
		}

		g.Go(func() error {
			return extractLayerToCache(gCtx, layer, diffID, lc, remaining)
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("extract layers: %w", err)
	}

	// Apply layers sequentially bottom-to-top (order matters for whiteouts).
	for i, diffID := range diffIDs {
		layerDir, ok := lc.Get(diffID)
		if !ok {
			return fmt.Errorf("layer %d (%s) missing from cache after extraction", i, diffID.String())
		}

		if err := applyLayerToDir(layerDir, dst); err != nil {
			return fmt.Errorf("apply layer %d (%s): %w", i, diffID.String(), err)
		}
	}

	return nil
}

// extractLayerToCache extracts a single layer into the layer cache.
// The remaining counter is shared across concurrent layer extractions to
// enforce a global size budget (prevents decompression bombs across layers).
func extractLayerToCache(ctx context.Context, layer v1.Layer, diffID v1.Hash, lc *LayerCache, remaining *atomic.Int64) error {
	tmpDir, err := lc.TempDir()
	if err != nil {
		return fmt.Errorf("create temp dir for layer %s: %w", diffID.String(), err)
	}

	rc, err := layer.Uncompressed()
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return fmt.Errorf("get uncompressed layer %s: %w", diffID.String(), err)
	}
	defer func() { _ = rc.Close() }()

	if err := extractTarSharedLimit(ctx, &contextReader{ctx: ctx, r: rc}, tmpDir, remaining); err != nil {
		_ = os.RemoveAll(tmpDir)
		return fmt.Errorf("extract layer %s: %w", diffID.String(), err)
	}

	if err := lc.Put(diffID, tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return fmt.Errorf("cache layer %s: %w", diffID.String(), err)
	}

	slog.Debug("layer extracted and cached", "diffID", diffID.String())
	return nil
}

// applyLayerToDir applies a cached layer directory to the destination rootfs.
// It handles OCI whiteout files for layer composition.
func applyLayerToDir(layerDir, dst string) error {
	return filepath.WalkDir(layerDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Compute the relative path within the layer.
		rel, err := filepath.Rel(layerDir, path)
		if err != nil {
			return fmt.Errorf("compute relative path: %w", err)
		}
		if rel == "." {
			return nil
		}

		// Handle whiteout files before copying.
		if isWhiteoutFile(rel) {
			if isOpaqueWhiteout(rel) {
				if err := applyOpaqueWhiteout(dst, filepath.Dir(rel)); err != nil {
					return fmt.Errorf("apply opaque whiteout %s: %w", rel, err)
				}
			} else {
				if err := applyWhiteout(dst, rel); err != nil {
					return fmt.Errorf("apply whiteout %s: %w", rel, err)
				}
			}
			// Don't copy whiteout files into the rootfs.
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		target := filepath.Join(dst, rel)

		// WalkDir uses lstat semantics, so d.Info() does not follow symlinks.
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", rel, err)
		}

		switch {
		case info.Mode()&os.ModeSymlink != 0:
			linkTarget, err := os.Readlink(path)
			if err != nil {
				return fmt.Errorf("readlink %s: %w", path, err)
			}

			// Validate symlink target stays within the rootfs.
			if filepath.IsAbs(linkTarget) {
				resolved := filepath.Join(dst, linkTarget)
				relCheck, err := filepath.Rel(dst, resolved)
				if err != nil || strings.HasPrefix(relCheck, "..") {
					return fmt.Errorf("symlink %q points outside rootfs: target %q", rel, linkTarget)
				}
			} else {
				symlinkDir := filepath.Dir(target)
				resolved := filepath.Clean(filepath.Join(symlinkDir, linkTarget))
				relCheck, err := filepath.Rel(dst, resolved)
				if err != nil || strings.HasPrefix(relCheck, "..") {
					return fmt.Errorf("symlink %q points outside rootfs: target %q", rel, linkTarget)
				}
			}

			// Remove any existing entry at target.
			if existing, err := os.Lstat(target); err == nil {
				if existing.IsDir() {
					return fmt.Errorf("refusing to replace directory with symlink: %s", target)
				}
				_ = os.Remove(target)
			}
			if err := os.Symlink(linkTarget, target); err != nil {
				return fmt.Errorf("create symlink %s: %w", rel, err)
			}

		case info.IsDir():
			mode := info.Mode().Perm() | 0o700
			if err := mkdirAllNoSymlink(dst, target, mode); err != nil {
				return fmt.Errorf("create directory %s: %w", rel, err)
			}
			if err := os.Chmod(target, mode); err != nil {
				return fmt.Errorf("set directory permissions %s: %w", rel, err)
			}

		case info.Mode().IsRegular():
			if err := copyFileToDir(path, target, dst, info.Mode().Perm()); err != nil {
				return fmt.Errorf("copy file %s: %w", rel, err)
			}

		default:
			// Skip special files (devices, fifos, etc.)
			return nil
		}

		// Preserve ownership from the cached layer entry. The cached
		// layer already has ownership set by extractTar's bestEffortLchown.
		copyOwnership(path, target)
		return nil
	})
}

// copyOwnership copies the uid/gid from src to dst using best-effort lchown.
func copyOwnership(src, dst string) {
	info, err := os.Lstat(src)
	if err != nil {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	bestEffortLchown(dst, int(stat.Uid), int(stat.Gid))
	xattr.CopyOverrideStat(src, dst)
}

// copyFileToDir copies a regular file from src to target within rootDir.
func copyFileToDir(src, target, rootDir string, mode os.FileMode) error {
	if err := mkdirAllNoSymlink(rootDir, filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	if err := validateNoSymlinkLeaf(target); err != nil {
		return err
	}

	mode |= 0o400 // Ensure at least owner-readable.

	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer func() { _ = srcFile.Close() }()

	dstFile, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create target: %w", err)
	}
	defer func() { _ = dstFile.Close() }()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return fmt.Errorf("copy contents: %w", err)
	}

	return nil
}

// extractTar reads a tar stream and extracts it to dst with security checks.
// The context is checked on each tar entry to support cancellation.
func extractTar(ctx context.Context, r io.Reader, dst string) error {
	// Wrap in a LimitedReader to prevent decompression bombs.
	lr := &io.LimitedReader{R: r, N: maxExtractSize}
	tr := tar.NewReader(lr)

	var entryCount int

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		entryCount++
		if entryCount > maxExtractEntries {
			return fmt.Errorf("tar archive exceeds maximum entry count of %d", maxExtractEntries)
		}

		target, err := sanitizeTarPath(dst, hdr.Name)
		if err != nil {
			slog.Warn("skipping unsafe tar entry", "name", hdr.Name, "err", err)
			continue
		}

		if err := extractTarEntry(tr, hdr, target, dst); err != nil {
			return fmt.Errorf("extract %q: %w", hdr.Name, err)
		}

		// Check if we've hit the size limit.
		if lr.N <= 0 {
			return fmt.Errorf("extracted data exceeds maximum allowed size of %d bytes", maxExtractSize)
		}
	}

	if entryCount == 0 {
		slog.Debug("tar archive has no entries, treating as empty layer")
	}

	return nil
}

// extractTarSharedLimit is like extractTar but uses a shared atomic counter
// for the size budget. This enforces a global maxExtractSize across all layers
// in a layered extraction, preventing decompression bombs via many layers.
// The context is checked on each tar entry to support cancellation.
func extractTarSharedLimit(ctx context.Context, r io.Reader, dst string, remaining *atomic.Int64) error {
	// Use an atomicLimitReader that decrements the shared counter.
	alr := &atomicLimitReader{R: r, Remaining: remaining}
	tr := tar.NewReader(alr)

	var entryCount int

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		entryCount++
		if entryCount > maxExtractEntries {
			return fmt.Errorf("tar archive exceeds maximum entry count of %d", maxExtractEntries)
		}

		target, err := sanitizeTarPath(dst, hdr.Name)
		if err != nil {
			slog.Warn("skipping unsafe tar entry", "name", hdr.Name, "err", err)
			continue
		}

		if err := extractTarEntry(tr, hdr, target, dst); err != nil {
			return fmt.Errorf("extract %q: %w", hdr.Name, err)
		}

		if remaining.Load() <= 0 {
			return fmt.Errorf("extracted data exceeds maximum allowed size of %d bytes", maxExtractSize)
		}
	}

	if entryCount == 0 {
		slog.Debug("tar archive has no entries, treating as empty layer")
	}

	return nil
}

// atomicLimitReader wraps an io.Reader and decrements a shared atomic counter.
// Multiple atomicLimitReaders can share the same Remaining counter to enforce
// a global read budget across concurrent readers.
type atomicLimitReader struct {
	R         io.Reader
	Remaining *atomic.Int64
}

func (r *atomicLimitReader) Read(p []byte) (n int, err error) {
	if r.Remaining.Load() <= 0 {
		return 0, fmt.Errorf("extracted data exceeds maximum allowed size of %d bytes", maxExtractSize)
	}
	n, err = r.R.Read(p)
	if n > 0 {
		r.Remaining.Add(-int64(n))
	}
	return n, err
}

// sanitizeTarPath validates and resolves a tar entry path to prevent path
// traversal attacks. Returns the cleaned absolute path under dst.
func sanitizeTarPath(dst, entryName string) (string, error) {
	return SanitizeTarPath(dst, entryName)
}

// mkdirAllNoSymlink creates directories one component at a time and refuses
// to traverse or overwrite symlinks.
func mkdirAllNoSymlink(destDir, targetDir string, mode os.FileMode) error {
	base := filepath.Clean(destDir)
	cleanTarget := filepath.Clean(targetDir)
	if cleanTarget != base && !strings.HasPrefix(cleanTarget, base+string(os.PathSeparator)) {
		return fmt.Errorf("invalid target directory: %s", targetDir)
	}

	rel, err := filepath.Rel(base, cleanTarget)
	if err != nil {
		return fmt.Errorf("compute relative path: %w", err)
	}
	if rel == "." {
		return nil
	}

	cur := base
	parts := strings.Split(rel, string(os.PathSeparator))
	for _, p := range parts {
		if p == "" || p == "." {
			continue
		}
		cur = filepath.Join(cur, p)
		info, err := os.Lstat(cur)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("refusing to traverse symlink during extraction: %s", cur)
			}
			if !info.IsDir() {
				return fmt.Errorf("path component is not a directory: %s", cur)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat directory %s: %w", cur, err)
		}
		if err := os.Mkdir(cur, mode); err != nil {
			return fmt.Errorf("create directory %s: %w", cur, err)
		}
	}
	return nil
}

// validateNoSymlinkLeaf checks that the target path is not a symlink or
// directory before writing a regular file. Uses os.Lstat to avoid following
// symlinks.
func validateNoSymlinkLeaf(target string) error {
	info, err := os.Lstat(target)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to write through symlink: %s", target)
		}
		if info.IsDir() {
			return fmt.Errorf("refusing to overwrite directory with file: %s", target)
		}
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	return fmt.Errorf("stat target %s: %w", target, err)
}

// extractTarEntry extracts a single tar entry to target. It handles files,
// directories, symlinks, and hard links with appropriate security checks.
//
//nolint:cyclop // tar entry type handling requires a switch with many cases
func extractTarEntry(tr *tar.Reader, hdr *tar.Header, target, rootDir string) error {
	switch hdr.Typeflag {
	case tar.TypeDir:
		mode := hdr.FileInfo().Mode().Perm() | 0o700
		if err := mkdirAllNoSymlink(rootDir, target, mode); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
		// Also chmod to handle existing directories from partial extractions.
		if err := os.Chmod(target, mode); err != nil {
			return fmt.Errorf("set directory permissions: %w", err)
		}

	case tar.TypeReg:
		if err := extractRegularFile(tr, hdr, target, rootDir); err != nil {
			return err
		}

	case tar.TypeSymlink:
		if err := extractSymlink(hdr, target, rootDir); err != nil {
			return err
		}

	case tar.TypeLink:
		if err := extractHardlink(hdr, target, rootDir); err != nil {
			return err
		}

	default:
		// Skip unsupported types (char/block devices, fifos, etc.)
		// These are not needed for a libkrun rootfs.
		slog.Debug("skipping unsupported tar entry type",
			"name", hdr.Name,
			"type", hdr.Typeflag,
		)
		return nil
	}

	// Best-effort ownership preservation from tar headers.
	// When running as non-root, Lchown will fail with EPERM — that's fine.
	bestEffortLchown(target, hdr.Uid, hdr.Gid)

	// On macOS, set the override_stat xattr so libkrun's virtiofs FUSE
	// server reports the tar entry's original ownership to the guest.
	// Note: uid/gid/mode come from untrusted OCI tar headers and are
	// intentionally forwarded — the guest is hardware-isolated and the
	// image author already controls everything the guest runs.
	xattr.SetOverrideStat(target, hdr.Uid, hdr.Gid, hdr.FileInfo().Mode())

	return nil
}

// extractRegularFile extracts a regular file from the tar stream.
func extractRegularFile(tr *tar.Reader, hdr *tar.Header, target, rootDir string) error {
	// Ensure parent directory exists without traversing symlinks.
	if err := mkdirAllNoSymlink(rootDir, filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	// Verify the target is not a symlink or directory before writing.
	if err := validateNoSymlinkLeaf(target); err != nil {
		return err
	}

	mode := hdr.FileInfo().Mode().Perm()
	// Ensure files are at least owner-readable.
	mode |= 0o400

	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Use io.Copy with the already-limited reader from the tar stream.
	if _, err := io.Copy(f, tr); err != nil {
		return fmt.Errorf("write file contents: %w", err)
	}

	return nil
}

// extractSymlink creates a symbolic link, validating that the link target
// does not escape the rootfs directory.
func extractSymlink(hdr *tar.Header, target, rootDir string) error {
	// Ensure parent directory exists without traversing symlinks.
	if err := mkdirAllNoSymlink(rootDir, filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory for symlink: %w", err)
	}

	linkTarget := hdr.Linkname

	// If the symlink target is absolute, verify it stays within rootDir
	// when resolved from within the rootfs.
	if filepath.IsAbs(linkTarget) {
		resolved := filepath.Join(rootDir, linkTarget)
		rel, err := filepath.Rel(rootDir, resolved)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("symlink %q points outside rootfs: target %q", hdr.Name, linkTarget)
		}
	} else {
		// For relative symlinks, resolve from the symlink's parent directory
		// and verify it doesn't escape.
		symlinkDir := filepath.Dir(target)
		resolved := filepath.Join(symlinkDir, linkTarget)
		resolved = filepath.Clean(resolved)
		rel, err := filepath.Rel(rootDir, resolved)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("symlink %q points outside rootfs: target %q", hdr.Name, linkTarget)
		}
	}

	// Check if the target is an existing directory -- refuse to replace
	// directories with symlinks.
	if info, err := os.Lstat(target); err == nil {
		if info.IsDir() {
			return fmt.Errorf("refusing to replace directory with symlink: %s", target)
		}
		_ = os.Remove(target)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat symlink target %s: %w", target, err)
	}

	if err := os.Symlink(linkTarget, target); err != nil {
		return fmt.Errorf("create symlink: %w", err)
	}

	return nil
}

// bestEffortLchown attempts to set uid/gid on a path without following symlinks.
// It silently ignores EPERM (non-root can't chown) and logs other errors at debug level.
func bestEffortLchown(path string, uid, gid int) {
	if err := os.Lchown(path, uid, gid); err != nil {
		if !os.IsPermission(err) {
			slog.Debug("lchown failed", "path", path, "uid", uid, "gid", gid, "err", err)
		}
	}
}

// extractHardlink creates a hard link, validating that both source and target
// remain within the rootfs directory.
func extractHardlink(hdr *tar.Header, target, rootDir string) error {
	// Ensure parent directory exists without traversing symlinks.
	if err := mkdirAllNoSymlink(rootDir, filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory for hardlink: %w", err)
	}

	// Resolve the link source within the rootfs.
	linkSrc := filepath.Join(rootDir, filepath.Clean(hdr.Linkname))

	// Verify the link source is within rootDir.
	rel, err := filepath.Rel(rootDir, linkSrc)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("hardlink %q source outside rootfs: %q", hdr.Name, hdr.Linkname)
	}

	// Only allow hardlinks to already-extracted, regular files within rootDir.
	srcInfo, err := os.Lstat(linkSrc)
	if err != nil {
		return fmt.Errorf("stat hardlink source %s: %w", linkSrc, err)
	}
	if srcInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing hardlink to symlink: %s", linkSrc)
	}
	if !srcInfo.Mode().IsRegular() {
		return fmt.Errorf("refusing hardlink to non-regular file: %s", linkSrc)
	}

	// Ensure the target itself is not a symlink (prevents writing through
	// a symlink placed by a previous tar entry at this location).
	if err := validateNoSymlinkLeaf(target); err != nil {
		return err
	}

	// Remove any existing entry before creating the hard link.
	_ = os.Remove(target)

	if err := os.Link(linkSrc, target); err != nil {
		return fmt.Errorf("create hardlink: %w", err)
	}

	return nil
}
