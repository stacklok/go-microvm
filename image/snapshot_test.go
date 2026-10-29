// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"archive/tar"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func pullLayers(t *testing.T, cache *Cache, ref string, layers ...v1.Layer) string {
	t.Helper()
	rootfs, err := PullWithFetcher(context.Background(), ref, cache, &mockFetcher{img: createImageFromLayers(t, layers...)})
	require.NoError(t, err)
	return rootfs.Path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

func TestChainIDs(t *testing.T) {
	t.Parallel()

	a := v1.Hash{Algorithm: "sha256", Hex: "aa"}
	b := v1.Hash{Algorithm: "sha256", Hex: "bb"}
	ab := chainIDs([]v1.Hash{a, b})
	require.Len(t, ab, 2)
	assert.Equal(t, a.String(), ab[0], "the first ChainID is the first DiffID")
	assert.NotEqual(t, ab[1], chainIDs([]v1.Hash{b, a})[1], "ChainIDs depend on layer order")
	assert.Equal(t, ab[1], chainIDs([]v1.Hash{a, b})[1])
}

func TestPullWithFetcher_ComposesFromSharedPrefix(t *testing.T) {
	t.Parallel()

	base := createLayerFromEntries(t, []tarEntry{
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "etc/base", typeflag: tar.TypeReg, mode: 0o644, content: "base"},
		{name: "etc/gone", typeflag: tar.TypeReg, mode: 0o644, content: "removed later"},
		{name: "usr/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "usr/sudo", typeflag: tar.TypeReg, mode: 0o4755, content: "sudo"},
	})
	tool := createLayerFromEntries(t, []tarEntry{
		{name: "opt/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "opt/tool", typeflag: tar.TypeReg, mode: 0o555, content: "tool"},
	})
	app := func(v string) v1.Layer {
		return createLayerFromEntries(t, []tarEntry{
			{name: "app", typeflag: tar.TypeReg, mode: 0o644, content: v},
			{name: "etc/.wh.gone", typeflag: tar.TypeReg, mode: 0o644},
			{name: "opt/tool", typeflag: tar.TypeReg, mode: 0o755, content: "tool " + v},
		})
	}

	cache := NewCache(t.TempDir())
	pullLayers(t, cache, "example.com/app:v1", base, tool, app("v1"))
	// Shares base and tool with v1: snapshot after them where trees clone.
	v2 := pullLayers(t, cache, "example.com/app:v2", base, tool, app("v2"))
	// Starts from that snapshot.
	v3 := pullLayers(t, cache, "example.com/app:v3", base, tool, app("v3"))

	for path, want := range map[string]string{
		filepath.Join(v2, "app"):      "v2",
		filepath.Join(v3, "app"):      "v3",
		filepath.Join(v3, "etc/base"): "base",
		filepath.Join(v3, "opt/tool"): "tool v3",
	} {
		assert.Equal(t, want, readFile(t, path), path)
	}
	_, err := os.Lstat(filepath.Join(v3, "etc", "gone"))
	assert.True(t, os.IsNotExist(err), "whiteout of the top layer applies on a cloned prefix")

	// The guest sees owners and modes, setuid included, through the
	// override_stat xattr; a cloned prefix keeps it.
	if os.Geteuid() != 0 {
		assert.Contains(t, overrideStat(t, filepath.Join(v3, "usr", "sudo")), "4755", "setuid survives the prefix clone")
	}

	cfg, err := createImageFromLayers(t, base, tool).ConfigFile()
	require.NoError(t, err)
	snapshot := cache.snapshotPath(chainIDs(cfg.RootFS.DiffIDs)[1])
	if runtime.GOOS == "darwin" {
		assert.DirExists(t, snapshot, "snapshot of the shared prefix")
		assert.Equal(t, "tool", readFile(t, filepath.Join(snapshot, "opt/tool")), "the snapshot is not changed by later layers")
	} else {
		assert.NoDirExists(t, snapshot, "no snapshots without directory clones")
	}
}

func TestPullWithFetcher_ComposesFromCachedRootfs(t *testing.T) {
	t.Parallel()

	base := createLayerFromEntries(t, []tarEntry{
		{name: "base", typeflag: tar.TypeReg, mode: 0o644, content: "base"},
	})
	top := createLayerFromEntries(t, []tarEntry{
		{name: "base", typeflag: tar.TypeReg, mode: 0o644, content: "replaced"},
		{name: "top", typeflag: tar.TypeReg, mode: 0o644, content: "top"},
	})

	cache := NewCache(t.TempDir())
	lower := pullLayers(t, cache, "example.com/base:1", base)
	upper := pullLayers(t, cache, "example.com/app:1", base, top)

	assert.Equal(t, "replaced", readFile(t, filepath.Join(upper, "base")))
	assert.Equal(t, "top", readFile(t, filepath.Join(upper, "top")))
	assert.Equal(t, "base", readFile(t, filepath.Join(lower, "base")), "the cached rootfs used as a prefix is not changed")
	_, err := os.Lstat(filepath.Join(lower, "top"))
	assert.True(t, os.IsNotExist(err))
}

func TestCache_PruneSnapshots(t *testing.T) {
	t.Parallel()

	base := createLayerFromEntries(t, []tarEntry{{name: "base", typeflag: tar.TypeReg, mode: 0o644, content: "base"}})
	a := createLayerFromEntries(t, []tarEntry{{name: "a", typeflag: tar.TypeReg, mode: 0o644, content: "a"}})
	b := createLayerFromEntries(t, []tarEntry{{name: "b", typeflag: tar.TypeReg, mode: 0o644, content: "b"}})

	cache := NewCache(t.TempDir())
	pullLayers(t, cache, "example.com/a:1", base, a)
	rootB := pullLayers(t, cache, "example.com/b:1", base, b)

	orphan := cache.snapshotPath("sha256:0000")
	require.NoError(t, os.MkdirAll(orphan, 0o700))
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(orphan, old, old))

	cfg, err := createImageFromLayers(t, base).ConfigFile()
	require.NoError(t, err)
	shared := cache.snapshotPath(chainIDs(cfg.RootFS.DiffIDs)[0])
	if _, err := os.Stat(shared); err == nil {
		require.NoError(t, os.Chtimes(shared, old, old))
	}

	removed, err := cache.PruneSnapshots(time.Hour)
	require.NoError(t, err)
	assert.Equal(t, 1, removed, "only the snapshot no cached rootfs starts with")
	assert.NoDirExists(t, orphan)

	require.NoError(t, removeTree(rootB))
	_, err = cache.PruneSnapshots(time.Hour)
	require.NoError(t, err)
	assert.NotContains(t, cache.recordedChains(), dirNameToDigest(filepath.Base(rootB)), "layer list of a removed rootfs is dropped")
}

func TestCopyFileToDir_ReplacesReadOnlyFile(t *testing.T) {
	t.Parallel()

	src := filepath.Join(t.TempDir(), "new")
	require.NoError(t, os.WriteFile(src, []byte("new"), 0o600))
	root := t.TempDir()
	target := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))
	require.NoError(t, os.Chmod(target, 0o444))

	require.NoError(t, copyFileToDir(src, target, root, 0o755))
	assert.Equal(t, "new", readFile(t, target))
	info, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}

func overrideStat(t *testing.T, path string) string {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, "user.containers.override_stat", buf)
	require.NoError(t, err)
	return string(buf[:n])
}
