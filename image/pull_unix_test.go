// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package image

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractTar_NonRootPreservesCreatedGroups(t *testing.T) {
	t.Parallel()

	if os.Geteuid() == 0 {
		t.Skip("ownership is restored when running as root")
	}
	groups, err := os.Getgroups()
	require.NoError(t, err)
	candidateGroups := append([]int{os.Getegid()}, groups...)

	dst := t.TempDir()
	controlDir := filepath.Join(dst, "control")
	require.NoError(t, os.Mkdir(controlDir, 0o755))
	require.NoError(t, os.Chmod(controlDir, 0o755))
	controlDirInfo, err := os.Lstat(controlDir)
	require.NoError(t, err)
	controlFile := filepath.Join(controlDir, "file.txt")
	require.NoError(t, os.WriteFile(controlFile, []byte("x"), 0o644))
	controlFileInfo, err := os.Lstat(controlFile)
	require.NoError(t, err)

	controlDirGID := controlDirInfo.Sys().(*syscall.Stat_t).Gid
	controlFileGID := controlFileInfo.Sys().(*syscall.Stat_t).Gid
	alternateGroup := func(baseline uint32) (int, bool) {
		for _, gid := range candidateGroups {
			if uint32(gid) != baseline {
				return gid, true
			}
		}
		return 0, false
	}
	dirGID, hasDirGID := alternateGroup(controlDirGID)
	fileGID, hasFileGID := alternateGroup(controlFileGID)
	if !hasDirGID || !hasFileGID {
		t.Skip("no permitted alternate group differs from the created group")
	}

	buf := createTarBuffer(t, []tarEntry{
		{name: "home/", typeflag: tar.TypeDir, mode: 0o755, uid: os.Geteuid(), gid: dirGID},
		{name: "home/file.txt", typeflag: tar.TypeReg, mode: 0o644, content: "x", uid: os.Geteuid(), gid: fileGID},
	})
	require.NoError(t, extractTar(context.Background(), buf, dst))

	for _, entry := range []struct {
		name string
		gid  uint32
	}{
		{name: "home", gid: controlDirGID},
		{name: "home/file.txt", gid: controlFileGID},
	} {
		info, err := os.Lstat(filepath.Join(dst, entry.name))
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		assert.Equal(t, entry.gid, stat.Gid, entry.name)
	}
}
