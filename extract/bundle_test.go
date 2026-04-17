// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBundle_Ensure_CacheDirIsPrivate(t *testing.T) {
	t.Parallel()

	// The cache holds an executable binary that will later be spawned. A
	// world- or group-writable cache permits local code injection; the
	// directory must be 0o700.
	cacheDir := filepath.Join(t.TempDir(), "cache")
	b := NewBundle("v-private", []File{
		{Name: "f", Content: []byte("x"), Mode: 0o644},
	})

	_, err := b.Ensure(cacheDir)
	require.NoError(t, err)

	info, err := os.Stat(cacheDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"cache dir must be 0o700; got %o", info.Mode().Perm())
}

func TestBundle_Ensure_ExtractsFiles(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	files := []File{
		{Name: "hello.txt", Content: []byte("hello"), Mode: 0o644},
		{Name: "bin/tool", Content: []byte("#!/bin/sh"), Mode: 0o755},
	}
	b := NewBundle("v1", files)

	dir, err := b.Ensure(cacheDir)
	require.NoError(t, err)

	// Verify file content.
	got, err := os.ReadFile(filepath.Join(dir, "hello.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), got)

	// Verify binary content and permissions.
	got, err = os.ReadFile(filepath.Join(dir, "bin", "tool"))
	require.NoError(t, err)
	assert.Equal(t, []byte("#!/bin/sh"), got)

	info, err := os.Stat(filepath.Join(dir, "bin", "tool"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}

func TestBundle_Ensure_Idempotent(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	files := []File{
		{Name: "data.bin", Content: []byte("content"), Mode: 0o644},
	}
	b := NewBundle("v1", files)

	dir1, err := b.Ensure(cacheDir)
	require.NoError(t, err)

	dir2, err := b.Ensure(cacheDir)
	require.NoError(t, err)

	assert.Equal(t, dir1, dir2)
}

func TestBundle_Ensure_VersionChange(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	files1 := []File{
		{Name: "data.txt", Content: []byte("v1 content"), Mode: 0o644},
	}
	files2 := []File{
		{Name: "data.txt", Content: []byte("v2 content"), Mode: 0o644},
	}

	b1 := NewBundle("v1", files1)
	dir1, err := b1.Ensure(cacheDir)
	require.NoError(t, err)

	b2 := NewBundle("v2", files2)
	dir2, err := b2.Ensure(cacheDir)
	require.NoError(t, err)

	assert.NotEqual(t, dir1, dir2)

	// Verify each directory has its own content.
	got1, err := os.ReadFile(filepath.Join(dir1, "data.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("v1 content"), got1)

	got2, err := os.ReadFile(filepath.Join(dir2, "data.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("v2 content"), got2)
}

func TestBundle_Ensure_Symlinks(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	files := []File{
		{Name: "libkrun.so.1", Content: []byte("library"), Mode: 0o755},
	}
	links := []Symlink{
		{Target: "libkrun.so.1", Name: "libkrun.so"},
	}
	b := NewBundle("v1", files, links...)

	dir, err := b.Ensure(cacheDir)
	require.NoError(t, err)

	// Verify symlink exists and points to the right target.
	linkPath := filepath.Join(dir, "libkrun.so")
	target, err := os.Readlink(linkPath)
	require.NoError(t, err)
	assert.Equal(t, "libkrun.so.1", target)

	// Verify symlink resolves to correct content.
	got, err := os.ReadFile(linkPath)
	require.NoError(t, err)
	assert.Equal(t, []byte("library"), got)
}

func TestBundle_Ensure_EmptyBundle(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	b := NewBundle("v1", nil)

	dir, err := b.Ensure(cacheDir)
	require.NoError(t, err)

	// Directory should exist with version file.
	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	versionData, err := os.ReadFile(filepath.Join(dir, ".version"))
	require.NoError(t, err)
	assert.NotEmpty(t, versionData)
}

func TestBundle_Ensure_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	files := []File{
		{Name: "shared.txt", Content: []byte("concurrent data"), Mode: 0o644},
	}
	b := NewBundle("v1", files)

	const numGoroutines = 10
	dirs := make([]string, numGoroutines)
	errs := make([]error, numGoroutines)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := range numGoroutines {
		go func(idx int) {
			defer wg.Done()
			dirs[idx], errs[idx] = b.Ensure(cacheDir)
		}(i)
	}
	wg.Wait()

	// All should succeed and return the same directory.
	for i := range numGoroutines {
		require.NoError(t, errs[i], "goroutine %d failed", i)
		assert.Equal(t, dirs[0], dirs[i], "goroutine %d returned different dir", i)
	}

	// Verify file content is not corrupted.
	got, err := os.ReadFile(filepath.Join(dirs[0], "shared.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("concurrent data"), got)
}

// --- Direct tests for computeHash and isValid ---

func TestBundle_ComputeHash_Stability(t *testing.T) {
	t.Parallel()

	files := []File{
		{Name: "a.txt", Content: []byte("aaa"), Mode: 0o644},
	}
	b := NewBundle("v1", files)

	hash1 := b.computeHash()
	hash2 := b.computeHash()

	assert.Equal(t, hash1, hash2, "same bundle should produce the same hash")
	assert.Len(t, hash1, 64, "SHA-256 hex digest should be 64 characters")

	// Verify it is valid hex.
	_, err := hex.DecodeString(hash1)
	require.NoError(t, err, "hash should be valid hex")
}

func TestBundle_ComputeHash_Sensitivity(t *testing.T) {
	t.Parallel()

	baseline := NewBundle("v1", []File{
		{Name: "a.txt", Content: []byte("hello"), Mode: 0o644},
	})
	baseHash := baseline.computeHash()

	tests := []struct {
		name  string
		build func() *Bundle
	}{
		{
			name: "different version",
			build: func() *Bundle {
				return NewBundle("v2", []File{
					{Name: "a.txt", Content: []byte("hello"), Mode: 0o644},
				})
			},
		},
		{
			name: "different content",
			build: func() *Bundle {
				return NewBundle("v1", []File{
					{Name: "a.txt", Content: []byte("world"), Mode: 0o644},
				})
			},
		},
		{
			name: "different filename",
			build: func() *Bundle {
				return NewBundle("v1", []File{
					{Name: "b.txt", Content: []byte("hello"), Mode: 0o644},
				})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			other := tt.build()
			assert.NotEqual(t, baseHash, other.computeHash(),
				"hash should differ when %s changes", tt.name)
		})
	}
}

func TestBundle_ComputeHash_EmptyBundle(t *testing.T) {
	t.Parallel()

	b1 := NewBundle("v1", nil)
	b2 := NewBundle("v2", nil)

	hash1 := b1.computeHash()
	hash2 := b2.computeHash()

	assert.Len(t, hash1, 64, "empty bundle hash should be valid 64-char hex")
	_, err := hex.DecodeString(hash1)
	require.NoError(t, err)

	assert.NotEqual(t, hash1, hash2,
		"empty bundles with different versions should produce different hashes")
}

func TestBundle_IsValid_MatchingHash(t *testing.T) {
	t.Parallel()

	b := NewBundle("v1", []File{
		{Name: "x.txt", Content: []byte("data"), Mode: 0o644},
	})
	hash := b.computeHash()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".version"), []byte(hash), 0o644))

	assert.True(t, b.isValid(dir, hash))
}

func TestBundle_IsValid_WrongHash(t *testing.T) {
	t.Parallel()

	b := NewBundle("v1", []File{
		{Name: "x.txt", Content: []byte("data"), Mode: 0o644},
	})
	hash := b.computeHash()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".version"), []byte("wronghash"), 0o644))

	assert.False(t, b.isValid(dir, hash))
}

func TestBundle_IsValid_MissingVersionFile(t *testing.T) {
	t.Parallel()

	b := NewBundle("v1", nil)
	hash := b.computeHash()

	dir := t.TempDir()
	// dir exists but has no .version file.
	assert.False(t, b.isValid(dir, hash))
}

func TestBundle_IsValid_NonexistentDir(t *testing.T) {
	t.Parallel()

	b := NewBundle("v1", nil)
	hash := b.computeHash()

	assert.False(t, b.isValid("/nonexistent/path/that/does/not/exist", hash))
}
