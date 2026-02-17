// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
