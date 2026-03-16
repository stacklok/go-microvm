// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRuntimeBundle_ExtractsFiles(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	runnerData := []byte("runner-binary")
	libkrunData := []byte("libkrun-data")

	src := RuntimeBundle("v1.0.0", runnerData, libkrunData)

	dir, err := src.Ensure(context.Background(), cacheDir)
	require.NoError(t, err)

	// Verify go-microvm-runner.
	got, err := os.ReadFile(filepath.Join(dir, RunnerBinaryName))
	require.NoError(t, err)
	assert.Equal(t, runnerData, got)

	info, err := os.Stat(filepath.Join(dir, RunnerBinaryName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())

	// Verify libkrun.
	libName := LibName("krun", 1)
	got, err = os.ReadFile(filepath.Join(dir, libName))
	require.NoError(t, err)
	assert.Equal(t, libkrunData, got)

	info, err = os.Stat(filepath.Join(dir, libName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}

func TestRuntimeBundle_Idempotent(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	src := RuntimeBundle("v1.0.0", []byte("runner"), []byte("lib"))

	dir1, err := src.Ensure(context.Background(), cacheDir)
	require.NoError(t, err)

	dir2, err := src.Ensure(context.Background(), cacheDir)
	require.NoError(t, err)

	assert.Equal(t, dir1, dir2)
}

func TestRuntimeBundle_DifferentVersions(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	src1 := RuntimeBundle("v1.0.0", []byte("runner-v1"), []byte("lib-v1"))
	src2 := RuntimeBundle("v2.0.0", []byte("runner-v2"), []byte("lib-v2"))

	dir1, err := src1.Ensure(context.Background(), cacheDir)
	require.NoError(t, err)

	dir2, err := src2.Ensure(context.Background(), cacheDir)
	require.NoError(t, err)

	assert.NotEqual(t, dir1, dir2)
}

func TestFirmwareBundle_ExtractsFirmware(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	fwData := []byte("firmware-data")

	src := FirmwareBundle("v5.0.0", 5, fwData)

	dir, err := src.Ensure(context.Background(), cacheDir)
	require.NoError(t, err)

	libName := LibName("krunfw", 5)
	got, err := os.ReadFile(filepath.Join(dir, libName))
	require.NoError(t, err)
	assert.Equal(t, fwData, got)
}

func TestFirmwareBundle_DifferentMajor(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	fwData := []byte("firmware-data")

	src := FirmwareBundle("v4.0.0", 4, fwData)

	dir, err := src.Ensure(context.Background(), cacheDir)
	require.NoError(t, err)

	libName := LibName("krunfw", 4)
	_, err = os.Stat(filepath.Join(dir, libName))
	require.NoError(t, err)
}

func TestDir_ExistingDirectory(t *testing.T) {
	t.Parallel()

	existingDir := t.TempDir()
	src := Dir(existingDir)

	dir, err := src.Ensure(context.Background(), "/ignored/cache")
	require.NoError(t, err)
	assert.Equal(t, existingDir, dir)
}

func TestDir_NonexistentDirectory(t *testing.T) {
	t.Parallel()

	src := Dir("/nonexistent/path/that/does/not/exist")

	_, err := src.Ensure(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "dir source")
}

func TestDir_NotADirectory(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "regular-file")
	require.NoError(t, os.WriteFile(filePath, []byte("hello"), 0o644))

	src := Dir(filePath)

	_, err := src.Ensure(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestBundleSource_EmptyCacheDir(t *testing.T) {
	t.Parallel()

	src := RuntimeBundle("v1.0.0", []byte("runner"), []byte("lib"))

	_, err := src.Ensure(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cache directory must not be empty")
}

func TestRuntimeBundle_ExtraLibs(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	runnerData := []byte("runner-binary")
	libkrunData := []byte("libkrun-data")
	epoxyData := []byte("libepoxy-data")
	virglData := []byte("virgl-data")

	src := RuntimeBundle("v1.0.0", runnerData, libkrunData,
		File{Name: "libepoxy.0.dylib", Content: epoxyData, Mode: 0o755},
		File{Name: "libvirglrenderer.1.dylib", Content: virglData, Mode: 0o755},
	)

	dir, err := src.Ensure(context.Background(), cacheDir)
	require.NoError(t, err)

	// Verify core files still present.
	got, err := os.ReadFile(filepath.Join(dir, RunnerBinaryName))
	require.NoError(t, err)
	assert.Equal(t, runnerData, got)

	got, err = os.ReadFile(filepath.Join(dir, LibName("krun", 1)))
	require.NoError(t, err)
	assert.Equal(t, libkrunData, got)

	// Verify extra libs.
	got, err = os.ReadFile(filepath.Join(dir, "libepoxy.0.dylib"))
	require.NoError(t, err)
	assert.Equal(t, epoxyData, got)

	got, err = os.ReadFile(filepath.Join(dir, "libvirglrenderer.1.dylib"))
	require.NoError(t, err)
	assert.Equal(t, virglData, got)
}

func TestRuntimeBundle_ConcurrentEnsure(t *testing.T) {
	t.Parallel()

	cacheDir := t.TempDir()
	src := RuntimeBundle("v1.0.0", []byte("runner-concurrent"), []byte("lib-concurrent"))

	const numGoroutines = 10
	dirs := make([]string, numGoroutines)
	errs := make([]error, numGoroutines)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := range numGoroutines {
		go func(idx int) {
			defer wg.Done()
			dirs[idx], errs[idx] = src.Ensure(context.Background(), cacheDir)
		}(i)
	}
	wg.Wait()

	for i := range numGoroutines {
		require.NoError(t, errs[i], "goroutine %d failed", i)
		assert.Equal(t, dirs[0], dirs[i], "goroutine %d returned different dir", i)
	}
}
