// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package virtiofs

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const overrideKey = "user.containers.override_stat"

// PrepareOwnership sets libkrun's override_stat ownership metadata on an
// authorized host entry or tree. relativePath must be "." for the whole root,
// or a non-empty relative path naming one entry and, if it is a directory, its
// subtree.
//
// The caller needs the OS permission required to read existing xattrs and to
// write new or changed metadata. A matching existing xattr is read but not
// rewritten. In particular, an unannotated host file with mode 0400 commonly
// rejects a new xattr from an unprivileged owner with EACCES; this function
// returns that error without changing host mode or ownership. It does not
// provide a way to choose an initial guest mode: a new xattr derives it from
// the host inode, while an existing xattr preserves its guest mode bits.
//
// The final component of root and every component of relativePath are opened
// without following symlinks. Symlinks below the selected target are skipped.
// Only directories and regular files are supported; encountering another file
// type fails the operation. The real host uid, gid, and mode are not changed.
// Existing mode permission, set-ID, and sticky bits are preserved in the
// override, while the requested uid and gid are reported to the guest.
//
// The caller authorizes the directory reached when root is opened and must
// trust and protect root's parent path while that acquisition occurs. All
// subsequent traversal is descriptor-relative, so mutable intermediate
// symlinks cannot escape that directory. Hard links inside root authorize the
// linked inode, even when that inode also has names outside root.
//
// Preparation is non-transactional. An error may leave earlier entries
// prepared. Callers must synchronize concurrent rename, creation, replacement,
// and guest chmod operations. The function provides neither cache invalidation
// nor atomic visibility to a running guest.
func PrepareOwnership(ctx context.Context, root, relativePath string, uid, gid uint32) error {
	if root == "" {
		return errors.New("virtiofs ownership root must not be empty")
	}
	parts, err := validateTarget(relativePath)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("prepare ownership %q: %w", relativePath, err)
	}

	fd, err := acquireTarget(root, relativePath, parts)
	if err != nil {
		return err
	}
	return prepareTree(ctx, fd, relativePath, uid, gid)
}

// acquireTarget pins the selected inode. Callers own the returned descriptor.
func acquireTarget(root, relativePath string, parts []string) (int, error) {
	// Cleaning removes a trailing slash or /. that would otherwise make
	// O_NOFOLLOW ineffective for a symlink in the final root component.
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

func prepareTree(ctx context.Context, fd int, displayPath string, uid, gid uint32) error {
	return prepareTreeWith(ctx, fd, displayPath, uid, gid, unix.Openat, func(file *os.File) ([]os.DirEntry, error) {
		return file.ReadDir(-1)
	})
}

func prepareTreeWith(
	ctx context.Context,
	fd int,
	displayPath string,
	uid, gid uint32,
	openat func(int, string, int, uint32) (int, error),
	readDir func(*os.File) ([]os.DirEntry, error),
) (retErr error) {
	file := os.NewFile(uintptr(fd), displayPath)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("open target %q: invalid file descriptor", displayPath)
	}
	defer func() {
		if err := file.Close(); err != nil && retErr == nil {
			retErr = fmt.Errorf("close %q: %w", displayPath, err)
		}
	}()

	if err := ctx.Err(); err != nil {
		return fmt.Errorf("prepare ownership %q: %w", displayPath, err)
	}

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return fmt.Errorf("stat %q: %w", displayPath, err)
	}
	typeBits := uint32(stat.Mode) & unix.S_IFMT
	if typeBits != unix.S_IFDIR && typeBits != unix.S_IFREG {
		return fmt.Errorf("prepare ownership %q: unsupported file type (mode %#o)", displayPath, stat.Mode)
	}
	if err := prepareEntry(fd, displayPath, uid, gid, uint32(stat.Mode)); err != nil {
		return err
	}
	if typeBits != unix.S_IFDIR {
		return nil
	}

	entries, err := readDir(file)
	if err != nil {
		return fmt.Errorf("read directory %q: %w", displayPath, err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("prepare ownership %q: %w", filepath.Join(displayPath, entry.Name()), err)
		}
		childPath := filepath.Join(displayPath, entry.Name())
		child, err := openat(fd, entry.Name(), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			if errors.Is(err, unix.ELOOP) {
				continue
			}
			return fmt.Errorf("open descendant %q without following symlinks: %w", childPath, err)
		}
		if err := prepareTreeWith(ctx, child, childPath, uid, gid, openat, readDir); err != nil {
			return err
		}
	}
	return nil
}

func prepareEntry(fd int, path string, uid, gid, hostMode uint32) error {
	return prepareEntryWith(fd, path, uid, gid, hostMode, unix.Fgetxattr, unix.Fsetxattr)
}

func prepareEntryWith(
	fd int,
	path string,
	uid, gid, hostMode uint32,
	getxattr func(int, string, []byte) (int, error),
	setxattr func(int, string, []byte, int) error,
) error {
	mode := hostMode
	buf := make([]byte, 256)
	n, err := getxattr(fd, overrideKey, buf)
	if err == nil {
		currentUID, currentGID, currentMode, parseErr := parseOverride(string(buf[:n]))
		if parseErr != nil {
			return fmt.Errorf("read existing override_stat on %q: %w", path, parseErr)
		}
		// Guest chmod changes only override_stat. Keep those permission, set-ID,
		// and sticky bits, but always take the type from the current inode.
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
	// libkrun's override_stat mode field is octal, including when it has no
	// leading zero. POSIX st_mode has no representable bits above 0177777.
	mode, err := strconv.ParseUint(parts[2], 8, 32)
	if err != nil || mode > 0o177777 {
		if err == nil {
			err = errors.New("mode exceeds POSIX st_mode bits")
		}
		return 0, 0, 0, fmt.Errorf("malformed mode in value %q: %w", value, err)
	}
	return uint32(uid), uint32(gid), uint32(mode), nil
}
