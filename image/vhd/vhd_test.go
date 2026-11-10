// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package vhd

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"github.com/stacklok/go-microvm/internal/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildFromDir(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		setup func(t *testing.T, rootfsDir string)
	}{
		{
			name: "regular file",
			setup: func(t *testing.T, rootfsDir string) {
				t.Helper()
				require.NoError(t, os.WriteFile(filepath.Join(rootfsDir, "hello.txt"), []byte("hello"), 0o644))
			},
		},
		{
			name: "rootfs metadata and symlink",
			setup: func(t *testing.T, rootfsDir string) {
				t.Helper()
				binDir := filepath.Join(rootfsDir, "usr", "bin")
				require.NoError(t, os.MkdirAll(binDir, 0o755))
				toolPath := filepath.Join(binDir, "tool")
				require.NoError(t, os.WriteFile(toolPath, []byte("#!/bin/sh\n"), 0o755))
				require.NoError(t, os.Symlink("tool", filepath.Join(binDir, "tool-link")))
				require.NoError(t, os.WriteFile(
					filepath.Join(rootfsDir, ".krun_config.json"),
					[]byte(`{"args":["/usr/bin/tool"]}`),
					0o644,
				))
				require.NoError(t, xattr.SetOverrideStat(toolPath, 123, 456, 0o4755))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rootfsDir := t.TempDir()
			tt.setup(t, rootfsDir)
			vhdPath := filepath.Join(rootfsDir, RootFSVHDName)

			require.NoError(t, BuildFromDir(t.Context(), rootfsDir, vhdPath))
			assertValidVHD(t, vhdPath)
			_, err := os.Stat(vhdPath + ".tmp")
			assert.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestBuildFromDir_ExcludesInTreeOutput(t *testing.T) {
	t.Parallel()

	rootfsDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootfsDir, "payload"), []byte("payload"), 0o644))
	inTreePath := filepath.Join(rootfsDir, RootFSVHDName)
	require.NoError(t, os.WriteFile(inTreePath, []byte("stale output must not be archived"), 0o644))
	require.NoError(t, os.WriteFile(inTreePath+".tmp", []byte("stale temp must not be archived"), 0o644))

	require.NoError(t, BuildFromDir(t.Context(), rootfsDir, inTreePath))
	inTreeInfo, err := os.Stat(inTreePath)
	require.NoError(t, err)

	baselineRootfsDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(baselineRootfsDir, "payload"), []byte("payload"), 0o644))
	outsidePath := filepath.Join(t.TempDir(), RootFSVHDName)
	require.NoError(t, BuildFromDir(t.Context(), baselineRootfsDir, outsidePath))
	outsideInfo, err := os.Stat(outsidePath)
	require.NoError(t, err)

	assert.Equal(t, outsideInfo.Size(), inTreeInfo.Size())
	assertValidVHD(t, inTreePath)
}

func TestBuildFromDir_InvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rootfs  string
		outPath string
		wantErr string
	}{
		{
			name:    "empty output path",
			rootfs:  t.TempDir(),
			outPath: "",
			wantErr: "output VHD path is empty",
		},
		{
			name:    "missing rootfs",
			rootfs:  filepath.Join(t.TempDir(), "missing"),
			outPath: filepath.Join(t.TempDir(), RootFSVHDName),
			wantErr: "stat rootfs directory",
		},
		{
			name:    "rootfs is a file",
			rootfs:  createFile(t),
			outPath: filepath.Join(t.TempDir(), RootFSVHDName),
			wantErr: "rootfs path is not a directory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := BuildFromDir(t.Context(), tt.rootfs, tt.outPath)
			require.Error(t, err)
			assert.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestBuildFromDir_CanceledContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	rootfsDir := t.TempDir()
	vhdPath := filepath.Join(rootfsDir, RootFSVHDName)

	err := BuildFromDir(ctx, rootfsDir, vhdPath)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	_, statErr := os.Stat(vhdPath)
	assert.ErrorIs(t, statErr, os.ErrNotExist)
	_, statErr = os.Stat(vhdPath + ".tmp")
	assert.ErrorIs(t, statErr, os.ErrNotExist)
}

func assertValidVHD(t *testing.T, vhdPath string) {
	t.Helper()

	_, err := tar2ext4.ReadExt4SuperBlock(vhdPath)
	require.NoError(t, err)

	file, err := os.Open(vhdPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, file.Close()) })

	fileSystemSize, blockSize, err := tar2ext4.Ext4FileSystemSize(file)
	require.NoError(t, err)
	assert.Positive(t, fileSystemSize)
	assert.Positive(t, blockSize)

	footer := make([]byte, 512)
	_, err = file.ReadAt(footer, fileSystemSize)
	require.NoError(t, err)
	assert.Equal(t, "conectix", string(footer[:8]))
}

func createFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "rootfs-file")
	require.NoError(t, os.WriteFile(path, []byte("not a directory"), 0o644))
	return path
}
