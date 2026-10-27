// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSetOverrideStat_OwnerReadOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode os.FileMode
		dir  bool
		want string
	}{
		{name: "file 0440", mode: 0o440, want: "0:0:0100440"},
		{name: "file 0400", mode: 0o400, want: "0:0:0100400"},
		{name: "setuid file 04555", mode: os.ModeSetuid | 0o555, want: "0:0:0104555"},
		{name: "directory 0555", mode: os.ModeDir | 0o555, dir: true, want: "0:0:040555"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "entry")
			if tt.dir {
				require.NoError(t, os.Mkdir(path, 0o700))
			} else {
				require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
			}
			perm := tt.mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
			//nolint:gosec // Test sets the read-only modes under test.
			require.NoError(t, os.Chmod(path, perm))
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

			require.NoError(t, SetOverrideStat(path, 0, 0, tt.mode))

			assert.Equal(t, tt.want, readXattr(t, path))
			info, err := os.Lstat(path)
			require.NoError(t, err)
			assert.Equal(t, perm, info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky), "host mode restored")
		})
	}
}

func TestSetOverrideStat_UnreadableTarget(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("root can bypass read permissions")
	}

	tests := []struct {
		name string
		mode os.FileMode
		dir  bool
	}{
		{name: "execute-only file", mode: 0o111},
		{name: "inaccessible file", mode: 0o000},
		{name: "execute-only directory", mode: 0o111, dir: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "entry")
			mode := tt.mode
			if tt.dir {
				require.NoError(t, os.Mkdir(path, 0o700))
				mode |= os.ModeDir
			} else {
				require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
			}
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })
			require.NoError(t, os.Chmod(path, tt.mode))

			require.NoError(t, SetOverrideStat(path, 0, 0, mode))
			info, err := os.Lstat(path)
			require.NoError(t, err)
			assert.Equal(t, tt.mode, info.Mode().Perm(), "unreadable target must not be chmod'ed")

			// Allow inspection without relying on xattr reads on an unreadable inode.
			require.NoError(t, os.Chmod(path, 0o600))
			_, err = unix.Lgetxattr(path, overrideKey, make([]byte, 256))
			assert.True(t, isNoAttribute(err), "override must be skipped, got %v", err)
		})
	}
}

func TestCopyOverrideStat_OwnerReadOnlyDestination(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(src, []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(dst, []byte("x"), 0o400))
	require.NoError(t, SetOverrideStat(src, 0, 0, 0o440))

	require.NoError(t, CopyOverrideStat(src, dst))

	assert.Equal(t, "0:0:0100440", readXattr(t, dst))
	info, err := os.Lstat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), info.Mode().Perm())
}

func TestLsetxattrWithFastPathSkipsFallback(t *testing.T) {
	t.Parallel()

	fallbackCalled := false
	err := lsetxattrWith("entry", "name", []byte("value"), func(string, string, []byte, int) error {
		return nil
	}, writableOps{
		open: func(string, int, uint32) (int, error) {
			fallbackCalled = true
			return -1, errors.New("unexpected fallback")
		},
	})

	require.NoError(t, err)
	assert.False(t, fallbackCalled)
}

func TestLsetxattrWithRejectsUnsupportedEntry(t *testing.T) {
	t.Parallel()

	chmodCalled := false
	setCalled := false
	var openFlags int
	err := lsetxattrWith("entry", "name", []byte("value"), func(string, string, []byte, int) error {
		return unix.EACCES
	}, writableOps{
		open: func(_ string, flags int, _ uint32) (int, error) {
			openFlags = flags
			return 7, nil
		},
		fstat: func(_ int, stat *unix.Stat_t) error {
			stat.Mode = unix.S_IFIFO | 0o444
			return nil
		},
		fchmod: func(int, uint32) error {
			chmodCalled = true
			return nil
		},
		fsetxattr: func(int, string, []byte, int) error {
			setCalled = true
			return nil
		},
		close: func(int) error { return nil },
	})

	assert.ErrorIs(t, err, unix.EACCES)
	assert.Equal(t, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, openFlags)
	assert.False(t, chmodCalled)
	assert.False(t, setCalled)
}

func TestLsetxattrWithRestoresPermissions(t *testing.T) {
	t.Parallel()

	var chmodModes []uint32
	err := lsetxattrWith("entry", "name", []byte("value"), func(string, string, []byte, int) error {
		return unix.EACCES
	}, testWritableOps(func(_ int, mode uint32) error {
		chmodModes = append(chmodModes, mode)
		return nil
	}, func(int, string, []byte, int) error { return nil }))

	require.NoError(t, err)
	assert.Equal(t, []uint32{0o644, 0o444}, chmodModes)
}

func TestPermissionRestoreError(t *testing.T) {
	t.Parallel()

	ordinary := errors.New("ordinary")
	restore := fmt.Errorf("%w: %w", ErrPermissionRestore, errors.New("restore"))
	assert.NoError(t, permissionRestoreError(ordinary))
	assert.ErrorIs(t, permissionRestoreError(restore), ErrPermissionRestore)
}

func TestLsetxattrWithReportsRestoreFailure(t *testing.T) {
	t.Parallel()

	restoreErr := errors.New("restore mode")
	calls := 0
	err := lsetxattrWith("entry", "name", []byte("value"), func(string, string, []byte, int) error {
		return unix.EPERM
	}, testWritableOps(func(_ int, _ uint32) error {
		calls++
		if calls == 2 {
			return restoreErr
		}
		return nil
	}, func(int, string, []byte, int) error { return nil }))

	assert.ErrorIs(t, err, ErrPermissionRestore)
	assert.ErrorIs(t, err, restoreErr)
}

func TestLsetxattrWithJoinsSetAndRestoreFailures(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("set xattr")
	restoreErr := errors.New("restore mode")
	calls := 0
	err := lsetxattrWith("entry", "name", []byte("value"), func(string, string, []byte, int) error {
		return unix.EPERM
	}, testWritableOps(func(_ int, _ uint32) error {
		calls++
		if calls == 2 {
			return restoreErr
		}
		return nil
	}, func(int, string, []byte, int) error { return writeErr }))

	assert.ErrorIs(t, err, ErrPermissionRestore)
	assert.ErrorIs(t, err, writeErr)
	assert.ErrorIs(t, err, restoreErr)
}

func TestLsetxattrWithDoesNotSetAfterChmodFailure(t *testing.T) {
	t.Parallel()

	chmodErr := errors.New("chmod")
	setCalled := false
	err := lsetxattrWith("entry", "name", []byte("value"), func(string, string, []byte, int) error {
		return unix.EACCES
	}, testWritableOps(func(_ int, _ uint32) error { return chmodErr }, func(int, string, []byte, int) error {
		setCalled = true
		return nil
	}))

	assert.ErrorIs(t, err, chmodErr)
	assert.False(t, setCalled)
}

func TestLsetxattrWithPinsReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	original := path + ".original"
	require.NoError(t, os.WriteFile(path, []byte("original"), 0o444))
	t.Cleanup(func() { _ = os.Chmod(original, 0o600) })

	ops := defaultWritableOps
	ops.fsetxattr = func(fd int, name string, value []byte, flags int) error {
		require.NoError(t, os.Rename(path, original))
		require.NoError(t, os.WriteFile(path, []byte("replacement"), 0o600))
		return unix.Fsetxattr(fd, name, value, flags)
	}
	err := lsetxattrWith(path, overrideKey, []byte("pinned"), func(string, string, []byte, int) error {
		return unix.EACCES
	}, ops)

	require.NoError(t, err)
	assert.Equal(t, "pinned", readXattr(t, original))
	_, err = unix.Lgetxattr(path, overrideKey, make([]byte, 32))
	assert.Error(t, err)
	info, err := os.Stat(original)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o444), info.Mode().Perm())
	info, err = os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func testWritableOps(fchmod func(int, uint32) error, fsetxattr func(int, string, []byte, int) error) writableOps {
	return writableOps{
		open: func(string, int, uint32) (int, error) { return 7, nil },
		fstat: func(_ int, stat *unix.Stat_t) error {
			stat.Mode = unix.S_IFREG | 0o444
			return nil
		},
		fchmod:    fchmod,
		fsetxattr: fsetxattr,
		close:     func(int) error { return nil },
	}
}
