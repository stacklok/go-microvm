// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package rootfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/stacklok/go-microvm/internal/xattr"
)

// CloneDir recursively clones srcDir into dstDir using platform-native COW
// primitives where available (FICLONE on Linux, clonefile on macOS), falling
// back to regular file copies. Directories are recreated with original
// permissions, symlinks that stay within the rootfs boundary are recreated,
// and file ownership is preserved on a best-effort basis (requires root).
//
// Symlinks whose targets would resolve outside dstDir are skipped to prevent
// rootfs hooks from writing through them to arbitrary host paths.
//
// dstDir must not already exist; it is created by CloneDir. If cloning fails
// after creating dstDir, CloneDir removes that destination before returning.
// Parent directories created to contain dstDir are preserved.
func CloneDir(srcDir, dstDir string) (retErr error) {
	// Guard: ensure srcDir is a real directory, not a symlink.
	srcInfo, err := os.Lstat(srcDir)
	if err != nil {
		return fmt.Errorf("lstat source dir: %w", err)
	}
	if srcInfo.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("source dir is a symlink: %s", srcDir)
	}
	if !srcInfo.IsDir() {
		return fmt.Errorf("source is not a directory: %s", srcDir)
	}

	// Stat through any parent symlinks for the permission bits.
	srcStat, err := os.Stat(srcDir)
	if err != nil {
		return fmt.Errorf("stat source dir: %w", err)
	}

	// Create the root destination directory. Ensure owner-write so we can
	// populate it; permissions are restored after the walk. Create parent
	// directories as before, but use Mkdir for the destination so an existing
	// path is always rejected rather than reused.
	srcPerm := srcStat.Mode().Perm()
	if err := os.MkdirAll(filepath.Dir(dstDir), srcPerm|0o700); err != nil {
		return fmt.Errorf("create destination parent dir: %w", err)
	}
	if err := os.Mkdir(dstDir, srcPerm|0o700); err != nil {
		return fmt.Errorf("create destination dir: %w", err)
	}

	// Track directories whose permissions were widened so we can restore
	// them after the walk completes (deepest first).
	type dirRestore struct {
		path string
		perm os.FileMode
	}
	dirsToRestore := []dirRestore{{path: dstDir, perm: srcPerm}}
	defer func() {
		if retErr == nil {
			return
		}

		// Make directories traversable and writable parent-first before removal.
		// This destination was created above, so cleanup never touches a caller's
		// pre-existing path.
		var cleanupErr error
		for _, dir := range dirsToRestore {
			if err := os.Chmod(dir.path, 0o700); err != nil && !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, fmt.Errorf("make clone directory writable %s: %w", dir.path, err))
			}
		}
		if err := os.RemoveAll(dstDir); err != nil {
			cleanupErr = errors.Join(cleanupErr, fmt.Errorf("remove clone destination: %w", err))
		}
		if cleanupErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("clean up failed clone destination: %w", cleanupErr))
		}
	}()

	walkErr := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, wErr error) error {
		if wErr != nil {
			return wErr
		}

		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return fmt.Errorf("computing relative path: %w", err)
		}

		// Skip the root directory itself (already created above).
		if relPath == "." {
			return nil
		}

		dstPath := filepath.Join(dstDir, relPath)

		// Handle symlinks with boundary validation.
		if d.Type()&fs.ModeSymlink != 0 {
			return cloneSymlink(path, dstPath, dstDir)
		}

		// Handle directories. Widen to owner-write so files can be placed
		// inside; we restore original permissions after the walk.
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return fmt.Errorf("stat directory %s: %w", relPath, err)
			}
			dirPerm := info.Mode().Perm()
			if err := os.MkdirAll(dstPath, dirPerm|0o700); err != nil {
				return fmt.Errorf("create directory %s: %w", relPath, err)
			}
			dirsToRestore = append(dirsToRestore, dirRestore{path: dstPath, perm: dirPerm})
			if err := bestEffortLchown(path, dstPath); err != nil {
				return fmt.Errorf("copy ownership for directory %s: %w", relPath, err)
			}
			return nil
		}

		// Handle regular files via platform-specific COW clone.
		if err := cloneFile(path, dstPath); err != nil {
			return fmt.Errorf("clone file %s: %w", relPath, err)
		}
		if err := bestEffortLchown(path, dstPath); err != nil {
			return fmt.Errorf("copy ownership for file %s: %w", relPath, err)
		}
		return nil
	})
	if walkErr != nil {
		return walkErr
	}

	// Restore original directory permissions in reverse order (deepest first)
	// so that restrictive parent permissions don't block child chmods.
	for i := len(dirsToRestore) - 1; i >= 0; i-- {
		_ = os.Chmod(dirsToRestore[i].path, dirsToRestore[i].perm)
	}

	// Copy the override_stat xattr on the root directory itself.
	// The walk skips "." so the root dir's xattr is not covered above.
	if err := xattr.CopyOverrideStat(srcDir, dstDir); err != nil {
		return fmt.Errorf("copy root override_stat: %w", err)
	}

	return nil
}

// cloneSymlink reads the target of src and recreates the symlink at dst,
// but only if the resolved target stays within rootDir. Symlinks that would
// escape the clone boundary are skipped to prevent rootfs hooks from writing
// through them to arbitrary host paths.
func cloneSymlink(src, dst, rootDir string) error {
	target, err := os.Readlink(src)
	if err != nil {
		return fmt.Errorf("readlink %s: %w", src, err)
	}

	// Resolve the target relative to the symlink's location within the
	// destination tree for boundary validation.
	var resolved string
	if filepath.IsAbs(target) {
		// Absolute symlink: re-root inside the destination directory.
		// e.g., /usr/lib/libfoo.so -> /rootDir/usr/lib/libfoo.so
		resolved = filepath.Join(rootDir, target)
	} else {
		// Relative symlink: resolve from the symlink's parent directory.
		resolved = filepath.Join(filepath.Dir(dst), target)
	}
	resolved = filepath.Clean(resolved)

	// Verify the resolved target stays within rootDir.
	absRoot, err := filepath.Abs(rootDir)
	if err != nil {
		return fmt.Errorf("abs rootdir: %w", err)
	}
	absResolved, err := filepath.Abs(resolved)
	if err != nil {
		return fmt.Errorf("abs resolved: %w", err)
	}

	rootPrefix := absRoot + string(filepath.Separator)
	if absResolved != absRoot && !strings.HasPrefix(absResolved, rootPrefix) {
		slog.Debug("skipping symlink escaping rootfs boundary",
			"src", src,
			"target", target,
			"resolved", absResolved,
		)
		return nil
	}

	return os.Symlink(target, dst)
}

// copyFile performs a regular file copy from src to dst, preserving permission
// bits. Setuid/setgid/sticky bits are stripped for security.
func copyFile(src, dst string) error {
	sf, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening source: %w", err)
	}
	defer func() { _ = sf.Close() }()

	info, err := sf.Stat()
	if err != nil {
		return fmt.Errorf("stat source: %w", err)
	}

	// Strip setuid/setgid/sticky — only preserve rwx permissions.
	mode := info.Mode().Perm()

	// Create with owner-write to allow the copy to succeed even for
	// read-only source files; restore the original mode after close.
	df, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode|0o200)
	if err != nil {
		return fmt.Errorf("creating destination: %w", err)
	}

	if _, err := io.Copy(df, sf); err != nil {
		_ = df.Close()
		return fmt.Errorf("copying data: %w", err)
	}

	if err := df.Close(); err != nil {
		return err
	}

	// Restore original permissions (may be read-only).
	return os.Chmod(dst, mode)
}

// bestEffortLchown copies the ownership (uid/gid) from src to dst without
// following symlinks. Lchown failures are ignored (non-root can't chown), but
// unsafe override_stat permission restoration failures are returned.
func bestEffortLchown(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return nil
	}
	uid, gid := fileOwner(info)
	if uid < 0 || gid < 0 {
		return nil
	}
	_ = os.Lchown(dst, uid, gid)
	return xattr.CopyOverrideStat(src, dst)
}
