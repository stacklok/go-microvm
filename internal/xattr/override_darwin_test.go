// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package xattr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSetOverrideStat_RegularFile(t *testing.T) {
	t.Parallel()

	f := filepath.Join(t.TempDir(), "test.txt")
	require.NoError(t, os.WriteFile(f, []byte("hello"), 0o644))

	SetOverrideStat(f, 0, 0, 0o644)

	assert.Equal(t, "0:0:0100644", readXattr(t, f))
}

func TestSetOverrideStat_ExecutableFile(t *testing.T) {
	t.Parallel()

	f := filepath.Join(t.TempDir(), "bin")
	require.NoError(t, os.WriteFile(f, []byte("#!/bin/sh"), 0o755))

	SetOverrideStat(f, 0, 0, 0o755)

	assert.Equal(t, "0:0:0100755", readXattr(t, f))
}

func TestSetOverrideStat_Directory(t *testing.T) {
	t.Parallel()

	d := filepath.Join(t.TempDir(), "dir")
	require.NoError(t, os.Mkdir(d, 0o755))

	SetOverrideStat(d, 1000, 1000, os.ModeDir|0o755)

	assert.Equal(t, "1000:1000:040755", readXattr(t, d))
}

func TestSetOverrideStat_RestrictiveMode(t *testing.T) {
	t.Parallel()

	f := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(f, []byte("secret"), 0o600))

	SetOverrideStat(f, 1000, 1000, 0o600)

	assert.Equal(t, "1000:1000:0100600", readXattr(t, f))
}

func TestSetOverrideStat_Symlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("data"), 0o644))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	SetOverrideStat(link, 0, 0, os.ModeSymlink|0o777)

	assert.Equal(t, "0:0:0120777", readXattr(t, link))
}

func TestSetOverrideStatFromPath(t *testing.T) {
	t.Parallel()

	f := filepath.Join(t.TempDir(), "test.sh")
	require.NoError(t, os.WriteFile(f, []byte("#!/bin/sh"), 0o755))

	SetOverrideStatFromPath(f, 0, 0)

	// Mode should be read from the file (regular + 0755).
	assert.Equal(t, "0:0:0100755", readXattr(t, f))
}

func TestCopyOverrideStat(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(src, []byte("data"), 0o644))
	require.NoError(t, os.WriteFile(dst, []byte("data"), 0o644))

	SetOverrideStat(src, 42, 42, 0o755)
	CopyOverrideStat(src, dst)

	assert.Equal(t, "42:42:0100755", readXattr(t, dst))
}

func TestCopyOverrideStat_NoXattr(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(src, []byte("data"), 0o644))
	require.NoError(t, os.WriteFile(dst, []byte("data"), 0o644))

	// No xattr on src — should be a no-op.
	CopyOverrideStat(src, dst)

	buf := make([]byte, 256)
	_, err := unix.Lgetxattr(dst, overrideKey, buf)
	assert.Error(t, err)
}

func TestGoFileModeToPosix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode os.FileMode
		want uint32
	}{
		{"regular 644", 0o644, 0o100644},
		{"regular 755", 0o755, 0o100755},
		{"regular 600", 0o600, 0o100600},
		{"dir 755", os.ModeDir | 0o755, 0o040755},
		{"dir 700", os.ModeDir | 0o700, 0o040700},
		{"symlink", os.ModeSymlink | 0o777, 0o120777},
		{"setuid", os.ModeSetuid | 0o755, 0o104755},
		{"setgid", os.ModeSetgid | 0o755, 0o102755},
		{"sticky", os.ModeSticky | 0o755, 0o101755},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := goFileModeToPosix(tt.mode)
			assert.Equal(t, tt.want, got)
		})
	}
}

func readXattr(t *testing.T, path string) string {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, overrideKey, buf)
	require.NoError(t, err)
	return string(buf[:n])
}
