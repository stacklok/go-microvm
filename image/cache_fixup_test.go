// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gofrs/flock"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/go-microvm/internal/pathutil"
)

func TestCache_EmptyStoragePath(t *testing.T) {
	for _, current := range []bool{false, true} {
		t.Run(fmt.Sprintf("currentFormat=%t", current), func(t *testing.T) {
			cwd := t.TempDir()
			require.NoError(t, os.Chmod(cwd, 0o700))
			t.Chdir(cwd)
			if current {
				require.NoError(t, os.WriteFile(cacheFormatFile, []byte(cacheFormat), 0o600))
			}
			for _, name := range []string{"sha256-abc", "sha256-" + testDiffID.Hex} {
				require.NoError(t, os.Mkdir(name, 0o700))
			}
			before, err := os.ReadDir(cwd)
			require.NoError(t, err)
			c := NewCache("")
			source := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(source, "keep"), nil, 0o600))
			require.False(t, c.Has("sha256:abc"))
			require.Error(t, c.Put("sha256:abc", source))
			path, err := c.TempDir()
			if path != "" {
				t.Cleanup(func() { _ = os.RemoveAll(path) })
			}
			require.Error(t, err)
			require.Empty(t, path)
			_, err = c.List()
			require.Error(t, err)
			_, err = c.Evict(time.Hour)
			require.Error(t, err)
			_, err = c.GC()
			require.Error(t, err)
			require.Error(t, c.Purge())
			c.StoreRef("example.com/img:1", "sha256:abc", &OCIConfig{})
			for _, lc := range []*LayerCache{NewLayerCache(""), c.LayerCache()} {
				require.False(t, lc.Has(testDiffID))
				require.Error(t, lc.Put(testDiffID, source))
				path, err := lc.TempDir()
				if path != "" {
					t.Cleanup(func() { _ = os.RemoveAll(path) })
				}
				require.Error(t, err)
				require.Empty(t, path)
				_, err = lc.Size()
				require.Error(t, err)
				_, err = lc.Evict(time.Hour)
				require.Error(t, err)
			}
			require.FileExists(t, filepath.Join(source, "keep"))
			after, err := os.ReadDir(cwd)
			require.NoError(t, err)
			require.Equal(t, before, after, "empty paths must not modify the working directory")
		})
	}
}

func TestCache_DirectFormatValidation(t *testing.T) {
	t.Parallel()
	for _, operation := range []string{"Get", "Has", "Put"} {
		t.Run(operation, func(t *testing.T) {
			c := NewCache(t.TempDir())
			digest := "sha256:abc"
			require.NoError(t, os.Mkdir(c.pathFor(digest), 0o700))
			source := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(source, "new"), nil, 0o600))
			switch operation {
			case "Get":
				path, hit := c.Get(digest)
				require.False(t, hit)
				require.Empty(t, path)
			case "Has":
				require.False(t, c.Has(digest))
			case "Put":
				require.NoError(t, c.Put(digest, source))
				path, hit := c.Get(digest)
				require.True(t, hit)
				require.FileExists(t, filepath.Join(path, "new"))
				require.True(t, c.Has(digest))
			}
		})
	}
}

func TestCache_FormatErrorPreservesSourceAndLayerHandleRetries(t *testing.T) {
	t.Parallel()
	c := NewCache(t.TempDir())
	lc := c.LayerCache()
	// A marker directory reliably produces an error, even for root.
	marker := filepath.Join(c.baseDir, cacheFormatFile)
	require.NoError(t, os.Mkdir(marker, 0o700))
	require.NoError(t, os.MkdirAll(lc.pathFor(testDiffID), 0o700))
	require.NoError(t, os.Mkdir(c.pathFor("sha256:abc"), 0o700))
	source := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(source, "keep"), nil, 0o600))
	require.False(t, c.Has("sha256:abc"))
	require.Error(t, c.Put("sha256:abc", source))
	require.False(t, lc.Has(testDiffID))
	path, hit := lc.Get(testDiffID)
	require.False(t, hit)
	require.Empty(t, path)
	require.Error(t, lc.Put(testDiffID, source))
	_, err := lc.TempDir()
	require.Error(t, err)
	_, err = lc.Size()
	require.Error(t, err)
	_, err = lc.Evict(time.Hour)
	require.Error(t, err)
	require.FileExists(t, filepath.Join(source, "keep"))

	require.NoError(t, os.Remove(marker))
	// The same handle retries, migrates old layers, and accepts fresh data.
	require.False(t, lc.Has(testDiffID))
	require.NoError(t, lc.Put(testDiffID, source))
	require.True(t, lc.Has(testDiffID))
	// Standalone handles do not infer/migrate a parent, even with its bad marker.
	require.NoError(t, os.Remove(marker))
	require.NoError(t, os.Mkdir(marker, 0o700))
	require.True(t, NewLayerCache(lc.baseDir).Has(testDiffID))
}

func TestCache_EvictOwnedEntriesOnly(t *testing.T) {
	t.Parallel()
	c := NewCache(t.TempDir())
	require.NoError(t, c.ensureFormat())
	old := time.Now().Add(-48 * time.Hour)
	for _, name := range []string{"refs", "layers", "notes", "tmp-caller", "sha256-fresh", "tmp-rootfs-fresh", "layers/sha256-fresh"} {
		require.NoError(t, os.MkdirAll(filepath.Join(c.baseDir, name), 0o700))
	}
	for _, name := range []string{"format", cacheFormatLock, "notes/file", "sha256-file", "tmp-format-old", "layers/sha256-file", "layers/notes"} {
		if name != "format" && name != cacheFormatLock {
			require.NoError(t, os.WriteFile(filepath.Join(c.baseDir, name), nil, 0o600))
		}
		require.NoError(t, os.Chtimes(filepath.Join(c.baseDir, name), old, old))
	}
	for _, name := range []string{"sha256-old", "tmp-rootfs-old", "tmp-stale-old", "layers/sha256-old", "layers/tmp-layer-old"} {
		path := filepath.Join(c.baseDir, name)
		require.NoError(t, os.MkdirAll(path, 0o700))
		require.NoError(t, os.Chtimes(path, old, old))
	}
	for _, name := range []string{"refs", "layers", "notes", "tmp-caller"} {
		require.NoError(t, os.Chtimes(filepath.Join(c.baseDir, name), old, old))
	}
	removed, err := c.Evict(24 * time.Hour)
	require.NoError(t, err)
	require.Equal(t, 6, removed)
	for _, name := range []string{"format", cacheFormatLock, "refs", "layers", "notes/file", "tmp-caller", "sha256-file", "layers/sha256-file", "layers/notes", "sha256-fresh", "tmp-rootfs-fresh", "layers/sha256-fresh"} {
		_, err := os.Stat(filepath.Join(c.baseDir, name))
		require.NoError(t, err, name)
	}
	require.True(t, c.Has("sha256:fresh"))
	require.True(t, c.LayerCache().Has(v1.Hash{Algorithm: "sha256", Hex: "fresh"}))
}

func TestCache_EvictLayerRecencyIsPerEntry(t *testing.T) {
	t.Parallel()
	c := NewCache(t.TempDir())
	lc := c.LayerCache()
	old := time.Now().Add(-48 * time.Hour)
	for _, hex := range []string{"active", "idle"} {
		diffID := v1.Hash{Algorithm: "sha256", Hex: hex}
		source, err := lc.TempDir()
		require.NoError(t, err)
		require.NoError(t, lc.Put(diffID, source))
		require.NoError(t, os.Chtimes(lc.pathFor(diffID), old, old))
	}
	require.True(t, lc.Has(v1.Hash{Algorithm: "sha256", Hex: "active"}))
	require.NoError(t, os.Chtimes(lc.baseDir, old, old))
	removed, err := c.Evict(24 * time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, removed)
	require.True(t, lc.Has(v1.Hash{Algorithm: "sha256", Hex: "active"}))
	require.False(t, lc.Has(v1.Hash{Algorithm: "sha256", Hex: "idle"}))
}

func TestCache_EvictDoesNotMigrate(t *testing.T) {
	t.Parallel()
	c := NewCache(t.TempDir())
	path := filepath.Join(c.baseDir, "layers", "sha256-fresh")
	require.NoError(t, os.MkdirAll(path, 0o700))
	removed, err := c.Evict(time.Hour)
	require.NoError(t, err)
	require.Zero(t, removed)
	require.DirExists(t, path)
	require.NoFileExists(t, filepath.Join(c.baseDir, cacheFormatFile))
}

func TestCache_ConcurrentMigration(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	c := NewCache(dir)
	require.NoError(t, os.Mkdir(c.pathFor("sha256:stale"), 0o700))
	tmp, err := os.MkdirTemp(dir, "tmp-rootfs-")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "keep"), nil, 0o600))
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	start := make(chan struct{})
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cache := NewCache(dir)
			source, err := cache.TempDir()
			if err == nil {
				err = cache.Put(fmt.Sprintf("sha256:fresh%d", i), source)
			}
			errs <- err
		}()
	}
	close(start)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("migration did not finish within lock timeout")
	}
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	for i := range 16 {
		require.True(t, c.Has(fmt.Sprintf("sha256:fresh%d", i)))
	}
	require.FileExists(t, filepath.Join(tmp, "keep"))
	require.NoDirExists(t, c.pathFor("sha256:stale"))
}

func TestCache_CurrentFormatDoesNotWaitForLock(t *testing.T) {
	t.Parallel()
	c := NewCache(t.TempDir())
	require.NoError(t, c.ensureFormat())
	lock := flock.New(filepath.Join(c.baseDir, cacheFormatLock))
	require.NoError(t, lock.Lock())
	defer lock.Unlock() //nolint:errcheck // test cleanup
	done := make(chan error, 1)
	go func() { done <- NewCache(c.baseDir).ensureFormat() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("current marker should bypass the migration lock")
	}
}

func TestCache_RejectsRawParentComponents(t *testing.T) {
	if !pathutil.KeepsSpecialBits() {
		t.Skip("host special bits require Linux nonroot")
	}
	public, err := os.MkdirTemp("/tmp", "cache-parent-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(public) })
	require.NoError(t, os.Chmod(public, 0o755))
	private := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(private, "sub"), 0o700))
	link := filepath.Join(public, "link")
	require.NoError(t, os.Symlink(filepath.Join(private, "sub"), link))
	// Keep this raw: Join would remove the parent component before validation.
	base := link + "/.."
	require.NoError(t, os.WriteFile(filepath.Join(public, cacheFormatFile), []byte(cacheFormat), 0o600))
	for _, name := range []string{"sha256-abc", "sha256-" + testDiffID.Hex} {
		require.NoError(t, os.Mkdir(filepath.Join(public, name), 0o755))
	}
	c := NewCache(base)
	source := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(source, "keep"), nil, 0o600))
	path, hit := c.Get("sha256:abc")
	require.False(t, hit)
	require.Empty(t, path)
	require.False(t, c.Has("sha256:abc"))
	require.Error(t, c.Put("sha256:abc", source))
	_, err = c.TempDir()
	require.Error(t, err)
	_, err = c.List()
	require.Error(t, err)
	_, err = c.Evict(time.Hour)
	require.Error(t, err)
	_, err = c.GC()
	require.Error(t, err)
	require.Error(t, c.Purge())
	c.StoreRef("example.com/img:1", "sha256:abc", &OCIConfig{})
	require.NoDirExists(t, filepath.Join(public, refDir))
	require.NoFileExists(t, filepath.Join(public, "sha256-abc", configFile))
	for _, lc := range []*LayerCache{NewLayerCache(base), c.LayerCache()} {
		path, hit := lc.Get(testDiffID)
		require.False(t, hit)
		require.Empty(t, path)
		require.False(t, lc.Has(testDiffID))
		require.Error(t, lc.Put(testDiffID, source))
		_, err = lc.TempDir()
		require.Error(t, err)
		_, err = lc.Size()
		require.Error(t, err)
		_, err = lc.Evict(time.Hour)
		require.Error(t, err)
	}
	require.FileExists(t, filepath.Join(source, "keep"))
	require.DirExists(t, filepath.Join(private, "sub"))
	data, err := os.ReadFile(filepath.Join(public, cacheFormatFile))
	require.NoError(t, err)
	require.Equal(t, cacheFormat, string(data))
}

func TestCache_RejectsLeafSymlinks(t *testing.T) {
	t.Parallel()
	for _, dangling := range []bool{false, true} {
		t.Run(fmt.Sprintf("dangling=%t", dangling), func(t *testing.T) {
			c := NewCache(t.TempDir())
			require.NoError(t, c.ensureFormat())
			lc := c.LayerCache()
			_, err := lc.TempDir()
			require.NoError(t, err)
			target := t.TempDir()
			if dangling {
				target = filepath.Join(target, "missing")
			}
			for _, entry := range []string{c.pathFor("sha256:abc"), lc.pathFor(testDiffID)} {
				require.NoError(t, os.Symlink(target, entry))
			}
			source := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(source, "keep"), nil, 0o600))
			require.False(t, c.Has("sha256:abc"))
			require.False(t, lc.Has(testDiffID))
			require.Error(t, c.Put("sha256:abc", source))
			require.Error(t, lc.Put(testDiffID, source))
			require.FileExists(t, filepath.Join(source, "keep"))
			entries, err := c.List()
			require.NoError(t, err)
			require.Empty(t, entries)
			c.StoreRef("example.com/img:1", "sha256:abc", &OCIConfig{})
			require.NoFileExists(t, filepath.Join(target, configFile))
			for _, entry := range []string{c.pathFor("sha256:abc"), lc.pathFor(testDiffID)} {
				info, err := os.Lstat(entry)
				require.NoError(t, err)
				require.NotZero(t, info.Mode()&os.ModeSymlink)
			}
		})
	}
	// Publication must not introduce a symlink entry either.
	c := NewCache(t.TempDir())
	lc := c.LayerCache()
	source := filepath.Join(t.TempDir(), "source")
	require.NoError(t, os.Symlink(t.TempDir(), source))
	require.Error(t, c.Put("sha256:abc", source))
	require.Error(t, lc.Put(testDiffID, source))
	_, err := os.Lstat(source)
	require.NoError(t, err)
	require.False(t, c.Has("sha256:abc"))
	require.False(t, lc.Has(testDiffID))
}

func TestCache_UnsafeBoundary(t *testing.T) {
	if !pathutil.KeepsSpecialBits() {
		t.Skip("host special bits require Linux nonroot")
	}
	dir, err := os.MkdirTemp("/tmp", "unsafe-cache-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))
	c := NewCache(dir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, cacheFormatFile), []byte(cacheFormat), 0o600))
	require.NoError(t, os.Mkdir(c.pathFor("sha256:abc"), 0o700))
	require.False(t, c.Has("sha256:abc"))
	_, err = c.TempDir()
	require.Error(t, err)
	source := t.TempDir()
	require.Error(t, c.Put("sha256:abc", source))
	require.DirExists(t, source)
	lc := NewLayerCache(dir)
	require.False(t, lc.Has(testDiffID))
	_, err = lc.TempDir()
	require.Error(t, err)
	require.Error(t, lc.Put(testDiffID, source))
	info, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}
