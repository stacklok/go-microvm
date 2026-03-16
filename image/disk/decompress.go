// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package disk

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

	"github.com/klauspost/compress/zstd"

	"github.com/stacklok/go-microvm/image"
)

// MaxDecompressedSize is the safety limit for decompression (30 GiB).
const MaxDecompressedSize int64 = 30 << 30

// Decompress reads zstd-compressed tar data from src and extracts it to destDir.
// It applies path traversal prevention, symlink safety checks, hardlink
// validation, and a decompression bomb limit of MaxDecompressedSize.
func Decompress(ctx context.Context, src io.Reader, destDir string) error {
	decoder, err := zstd.NewReader(src)
	if err != nil {
		return fmt.Errorf("create zstd decoder: %w", err)
	}
	defer decoder.Close()

	tr := tar.NewReader(decoder)

	var totalSize int64
	var entryCount int

	for {
		// Check context cancellation periodically.
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("decompression cancelled: %w", err)
		}

		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar header: %w", err)
		}

		entryCount++

		target, err := image.SanitizeTarPath(destDir, hdr.Name)
		if err != nil {
			slog.Warn("skipping unsafe tar entry", "name", hdr.Name, "err", err)
			continue
		}

		if err := extractEntry(ctx, tr, hdr, target, destDir, &totalSize); err != nil {
			return fmt.Errorf("extract %q: %w", hdr.Name, err)
		}

		if totalSize > MaxDecompressedSize {
			return fmt.Errorf("extracted data exceeds maximum allowed size of %d bytes", MaxDecompressedSize)
		}
	}

	if entryCount == 0 {
		return fmt.Errorf("tar archive is empty or contains no valid entries")
	}

	return nil
}

// extractEntry extracts a single tar entry to target with security checks.
//
//nolint:cyclop // tar entry type handling requires a switch with many cases
func extractEntry(ctx context.Context, tr *tar.Reader, hdr *tar.Header, target, rootDir string, totalSize *int64) error {
	switch hdr.Typeflag {
	case tar.TypeDir:
		mode := hdr.FileInfo().Mode().Perm() | 0o700
		if err := image.MkdirAllNoSymlink(rootDir, target, mode); err != nil {
			return fmt.Errorf("create directory: %w", err)
		}
		if err := os.Chmod(target, mode); err != nil {
			return fmt.Errorf("set directory permissions: %w", err)
		}

	case tar.TypeReg:
		if err := extractRegFile(ctx, tr, hdr, target, rootDir, totalSize); err != nil {
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
		slog.Debug("skipping unsupported tar entry type",
			"name", hdr.Name,
			"type", hdr.Typeflag,
		)
	}

	return nil
}

// extractRegFile extracts a regular file from the tar stream with size tracking.
func extractRegFile(_ context.Context, tr *tar.Reader, hdr *tar.Header, target, rootDir string, totalSize *int64) error {
	if err := image.MkdirAllNoSymlink(rootDir, filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory: %w", err)
	}

	if err := image.ValidateNoSymlinkLeaf(target); err != nil {
		return err
	}

	mode := hdr.FileInfo().Mode().Perm() | 0o400

	f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer func() { _ = f.Close() }()

	n, err := io.Copy(f, tr)
	if err != nil {
		return fmt.Errorf("write file contents: %w", err)
	}

	*totalSize += n
	return nil
}

// extractSymlink creates a symbolic link, validating that the link target
// does not escape the root directory.
func extractSymlink(hdr *tar.Header, target, rootDir string) error {
	if err := image.MkdirAllNoSymlink(rootDir, filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory for symlink: %w", err)
	}

	linkTarget := hdr.Linkname

	if filepath.IsAbs(linkTarget) {
		resolved := filepath.Join(rootDir, linkTarget)
		rel, err := filepath.Rel(rootDir, resolved)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("symlink %q points outside root: target %q", hdr.Name, linkTarget)
		}
	} else {
		symlinkDir := filepath.Dir(target)
		resolved := filepath.Clean(filepath.Join(symlinkDir, linkTarget))
		rel, err := filepath.Rel(rootDir, resolved)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("symlink %q points outside root: target %q", hdr.Name, linkTarget)
		}
	}

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
// remain within the root directory.
func extractHardlink(hdr *tar.Header, target, rootDir string) error {
	if err := image.MkdirAllNoSymlink(rootDir, filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent directory for hardlink: %w", err)
	}

	linkSrc := filepath.Join(rootDir, filepath.Clean(hdr.Linkname))

	rel, err := filepath.Rel(rootDir, linkSrc)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("hardlink %q source outside root: %q", hdr.Name, hdr.Linkname)
	}

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

	if err := image.ValidateNoSymlinkLeaf(target); err != nil {
		return err
	}

	_ = os.Remove(target)

	if err := os.Link(linkSrc, target); err != nil {
		return fmt.Errorf("create hardlink: %w", err)
	}

	return nil
}
