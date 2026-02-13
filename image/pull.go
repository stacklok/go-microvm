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
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
)

// maxExtractSize is a safety limit to prevent decompression bombs.
// 30 GB should be generous enough for any legitimate container image.
const maxExtractSize int64 = 30 << 30 // 30 GiB

// Pull fetches an OCI image, flattens its layers, and extracts to a directory.
// If a Cache is provided, results are cached by image digest. The returned
// RootFS contains the extraction path and parsed OCI config.
func Pull(ctx context.Context, imageRef string, cache *Cache) (*RootFS, error) {
	return PullWithFetcher(ctx, imageRef, cache, nil)
}

// PullWithFetcher is like Pull but uses the provided ImageFetcher instead of crane.
// If fetcher is nil, the default CraneFetcher is used.
func PullWithFetcher(ctx context.Context, imageRef string, cache *Cache, fetcher ImageFetcher) (*RootFS, error) {
	if fetcher == nil {
		fetcher = CraneFetcher{}
	}

	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, fmt.Errorf("parse image reference %q: %w", imageRef, err)
	}

	slog.Debug("pulling image", "ref", ref.String())

	img, err := fetcher.Pull(ctx, ref.String())
	if err != nil {
		return nil, fmt.Errorf("pull image %q: %w", imageRef, err)
	}

	// Compute the manifest digest for cache keying.
	digest, err := img.Digest()
	if err != nil {
		return nil, fmt.Errorf("compute image digest: %w", err)
	}

	digestStr := digest.String()
	slog.Debug("image digest", "digest", digestStr)

	// Check cache before extracting.
	if cache != nil {
		if cachedPath, ok := cache.Get(digestStr); ok {
			slog.Debug("using cached rootfs", "path", cachedPath)
			ociCfg, err := extractOCIConfig(img)
			if err != nil {
				return nil, fmt.Errorf("extract OCI config: %w", err)
			}
			return &RootFS{Path: cachedPath, Config: ociCfg}, nil
		}
	}

	// Extract OCI config.
	ociCfg, err := extractOCIConfig(img)
	if err != nil {
		return nil, fmt.Errorf("extract OCI config: %w", err)
	}

	// Create a temporary directory for extraction.
	tmpDir, err := os.MkdirTemp("", "propolis-rootfs-*")
	if err != nil {
		return nil, fmt.Errorf("create temp dir for rootfs: %w", err)
	}

	// Extract the flattened filesystem.
	if err := extractImage(img, tmpDir); err != nil {
		_ = os.RemoveAll(tmpDir)
		return nil, fmt.Errorf("extract image layers: %w", err)
	}

	// Move into cache if available.
	rootfsPath := tmpDir
	if cache != nil {
		if err := cache.Put(digestStr, tmpDir); err != nil {
			_ = os.RemoveAll(tmpDir)
			return nil, fmt.Errorf("cache rootfs: %w", err)
		}
		// After Put, the canonical path is in the cache.
		if cachedPath, ok := cache.Get(digestStr); ok {
			rootfsPath = cachedPath
		}
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

// extractImage flattens all image layers into a single tar stream and extracts
// it to the destination directory. It includes security measures against path
// traversal, symlink attacks, and decompression bombs.
func extractImage(img v1.Image, dst string) error {
	reader := mutate.Extract(img)
	defer func() { _ = reader.Close() }()

	return extractTar(reader, dst)
}

// extractTar reads a tar stream and extracts it to dst with security checks.
func extractTar(r io.Reader, dst string) error {
	// Wrap in a LimitedReader to prevent decompression bombs.
	lr := &io.LimitedReader{R: r, N: maxExtractSize}
	tr := tar.NewReader(lr)

	var entryCount int

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		entryCount++

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
		return fmt.Errorf("tar archive is empty or contains no valid entries")
	}

	return nil
}

// sanitizeTarPath validates and resolves a tar entry path to prevent path
// traversal attacks. Returns the cleaned absolute path under dst.
func sanitizeTarPath(dst, entryName string) (string, error) {
	// Clean the entry name to remove any ".." or "." components.
	cleaned := filepath.Clean(entryName)

	// Reject absolute paths in tar entries.
	if filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("path traversal detected: absolute path %q in tar entry", entryName)
	}

	// Join with the destination, then verify it's actually under dst.
	target := filepath.Join(dst, cleaned)

	// Resolve symlinks in the destination prefix so that a crafted symlink
	// earlier in the archive can't redirect later entries outside the rootfs.
	relPath, err := filepath.Rel(dst, target)
	if err != nil {
		return "", fmt.Errorf("compute relative path: %w", err)
	}

	if strings.HasPrefix(relPath, "..") || relPath == ".." {
		return "", fmt.Errorf("path traversal detected: %q resolves outside destination", entryName)
	}

	return target, nil
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
	}

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
