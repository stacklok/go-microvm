// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// PrepareOwnership prepares a selected tree using descriptor-relative,
// symlink-confined traversal. In strict mode the first entry failure is
// returned. Otherwise recoverable entry failures are collected and traversal
// continues where it is safe; target acquisition and cancellation always fail.
func PrepareOwnership(ctx context.Context, root, relativePath string, uid, gid uint32, strict bool) (PreparationReport, error) {
	var report PreparationReport
	if root == "" {
		return report, errors.New("virtiofs ownership root must not be empty")
	}
	parts, err := validateTarget(relativePath)
	if err != nil {
		return report, err
	}
	if err := ctx.Err(); err != nil {
		return report, fmt.Errorf("prepare ownership %q: %w", relativePath, err)
	}
	fd, err := acquireTarget(root, relativePath, parts)
	if err != nil {
		return report, err
	}
	err = prepareTree(ctx, fd, relativePath, uid, gid, strict, &report)
	return report, err
}

// SetOverrideStatTree strictly prepares the entire root for virtio-fs ownership mapping.
func SetOverrideStatTree(root string, uid, gid int) error {
	if uid < 0 || gid < 0 || uint64(uid) > math.MaxUint32 || uint64(gid) > math.MaxUint32 {
		return fmt.Errorf("override_stat uid/gid out of uint32 range: %d:%d", uid, gid)
	}
	_, err := PrepareOwnership(context.Background(), root, ".", uint32(uid), uint32(gid), true)
	return err
}

func acquireTarget(root, relativePath string, parts []string) (int, error) {
	root = filepath.Clean(root)
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, fmt.Errorf("open authorized root %q without following symlinks: %w", root, err)
	}
	if len(parts) == 0 {
		return fd, nil
	}
	current := fd
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(current, part, flags, 0)
		if closeErr := unix.Close(current); closeErr != nil && openErr == nil {
			if next >= 0 {
				_ = unix.Close(next)
			}
			return -1, fmt.Errorf("close target parent %q: %w", filepath.Join(parts[:i]...), closeErr)
		}
		if openErr != nil {
			return -1, fmt.Errorf("open target %q without following symlinks: %w", relativePath, openErr)
		}
		current = next
	}
	return current, nil
}

func validateTarget(relativePath string) ([]string, error) {
	if relativePath == "" {
		return nil, errors.New("virtiofs ownership target must not be empty")
	}
	if filepath.IsAbs(relativePath) {
		return nil, fmt.Errorf("virtiofs ownership target %q must be relative", relativePath)
	}
	if relativePath == "." {
		return nil, nil
	}
	parts := strings.Split(relativePath, string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, fmt.Errorf("virtiofs ownership target %q contains an invalid path component", relativePath)
		}
	}
	return parts, nil
}

func prepareTree(ctx context.Context, fd int, displayPath string, uid, gid uint32, strict bool, report *PreparationReport) error {
	return prepareTreeWith(ctx, fd, displayPath, uid, gid, strict, report, unix.Openat, func(file *os.File) ([]os.DirEntry, error) {
		return file.ReadDir(-1)
	})
}

func prepareTreeWith(ctx context.Context, fd int, displayPath string, uid, gid uint32, strict bool, report *PreparationReport, openat func(int, string, int, uint32) (int, error), readDir func(*os.File) ([]os.DirEntry, error)) (retErr error) {
	file := os.NewFile(uintptr(fd), displayPath)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open target %q: invalid file descriptor", displayPath)
	}
	defer func() {
		if err := file.Close(); err != nil {
			closeErr := fmt.Errorf("close %q: %w", displayPath, err)
			if strict && retErr == nil {
				retErr = closeErr
			} else if !strict {
				report.add(closeErr)
			}
		}
	}()
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("prepare ownership %q: %w", displayPath, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return handleEntryError(fmt.Errorf("stat %q: %w", displayPath, err), strict, report)
	}
	typeBits := uint32(stat.Mode) & unix.S_IFMT
	if typeBits != unix.S_IFDIR && typeBits != unix.S_IFREG {
		return handleEntryError(fmt.Errorf("prepare ownership %q: unsupported file type (mode %#o)", displayPath, stat.Mode), strict, report)
	}
	if err := prepareEntry(fd, displayPath, uid, gid, uint32(stat.Mode)); err != nil {
		if strict {
			return err
		}
		report.add(err)
	}
	if typeBits != unix.S_IFDIR {
		return nil
	}
	entries, err := readDir(file)
	if err != nil {
		return handleEntryError(fmt.Errorf("read directory %q: %w", displayPath, err), strict, report)
	}
	for _, entry := range entries {
		childPath := filepath.Join(displayPath, entry.Name())
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("prepare ownership %q: %w", childPath, err)
		}
		child, err := openat(fd, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				continue
			}
			err = fmt.Errorf("open descendant %q without following symlinks: %w", childPath, err)
			if strict {
				return err
			}
			report.add(err)
			continue
		}
		if err := prepareTreeWith(ctx, child, childPath, uid, gid, strict, report, openat, readDir); err != nil {
			return err
		}
	}
	return nil
}

func handleEntryError(err error, strict bool, report *PreparationReport) error {
	if strict {
		return err
	}
	report.add(err)
	return nil
}

func prepareEntry(fd int, path string, uid, gid, hostMode uint32) error {
	return prepareEntryWith(fd, path, uid, gid, hostMode, unix.Fgetxattr, unix.Fsetxattr)
}

func prepareEntryWith(fd int, path string, uid, gid, hostMode uint32, getxattr func(int, string, []byte) (int, error), setxattr func(int, string, []byte, int) error) error {
	mode := hostMode
	buf := make([]byte, 256)
	n, err := getxattr(fd, overrideKey, buf)
	if err == nil {
		currentUID, currentGID, currentMode, parseErr := parseOverride(string(buf[:n]))
		if parseErr != nil {
			return fmt.Errorf("read existing override_stat on %q: %w", path, parseErr)
		}
		mode = hostMode&unix.S_IFMT | currentMode&0o7777
		if currentUID == uid && currentGID == gid && currentMode == mode {
			return nil
		}
	} else if !isNoAttribute(err) {
		return fmt.Errorf("read override_stat on %q: %w", path, err)
	}
	desired := fmt.Sprintf("%d:%d:0%o", uid, gid, mode)
	if err := setxattr(fd, overrideKey, []byte(desired), 0); err != nil {
		return fmt.Errorf("write override_stat on %q: %w", path, err)
	}
	return nil
}

func parseOverride(value string) (uint32, uint32, uint32, error) {
	parts := strings.Split(value, ":")
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("malformed value %q", value)
	}
	uid, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("malformed uid in value %q: %w", value, err)
	}
	gid, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("malformed gid in value %q: %w", value, err)
	}
	mode, err := strconv.ParseUint(parts[2], 8, 32)
	if err != nil || mode > 0o177777 {
		if err == nil {
			err = errors.New("mode exceeds POSIX st_mode bits")
		}
		return 0, 0, 0, fmt.Errorf("malformed mode in value %q: %w", value, err)
	}
	return uint32(uid), uint32(gid), uint32(mode), nil
}
