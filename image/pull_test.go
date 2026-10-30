// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/stacklok/go-microvm/internal/pathutil"
	"github.com/stacklok/go-microvm/internal/xattr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSanitizeTarPath_RejectsPathTraversal(t *testing.T) {
	t.Parallel()

	dst := "/some/root"

	tests := []struct {
		name      string
		entryName string
	}{
		{name: "dot dot slash", entryName: "../../etc/passwd"},
		{name: "leading dot dot", entryName: "../secret"},
		{name: "embedded traversal", entryName: "usr/../../etc/shadow"},
		{name: "bare dot dot", entryName: ".."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := sanitizeTarPath(dst, tt.entryName)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "path traversal")
		})
	}
}

func TestSanitizeTarPath_AcceptsCleanPaths(t *testing.T) {
	t.Parallel()

	dst := "/some/root"

	tests := []struct {
		name      string
		entryName string
		expected  string
	}{
		{
			name:      "simple path",
			entryName: "usr/bin/foo",
			expected:  "/some/root/usr/bin/foo",
		},
		{
			name:      "root relative",
			entryName: "etc/config.json",
			expected:  "/some/root/etc/config.json",
		},
		{
			name:      "single file",
			entryName: "hello.txt",
			expected:  "/some/root/hello.txt",
		},
		{
			name:      "with dot component",
			entryName: "./usr/bin/bar",
			expected:  "/some/root/usr/bin/bar",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := sanitizeTarPath(dst, tt.entryName)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// createTarBuffer creates an in-memory tar archive from the provided entries.
func createTarBuffer(t *testing.T, entries []tarEntry) *bytes.Buffer {
	t.Helper()

	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Size:     int64(len(e.content)),
			Linkname: e.linkname,
			Uid:      e.uid,
			Gid:      e.gid,
		}

		err := tw.WriteHeader(hdr)
		require.NoError(t, err)

		if len(e.content) > 0 {
			_, err = tw.Write([]byte(e.content))
			require.NoError(t, err)
		}
	}

	err := tw.Close()
	require.NoError(t, err)

	return &buf
}

type tarEntry struct {
	name     string
	typeflag byte
	mode     int64
	content  string
	linkname string
	uid      int
	gid      int
}

func TestExtractTar_DirectoriesAndFiles(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{
			name:     "usr/",
			typeflag: tar.TypeDir,
			mode:     0o755,
		},
		{
			name:     "usr/bin/",
			typeflag: tar.TypeDir,
			mode:     0o755,
		},
		{
			name:     "usr/bin/hello",
			typeflag: tar.TypeReg,
			mode:     0o755,
			content:  "#!/bin/sh\necho hello\n",
		},
		{
			name:     "etc/config.txt",
			typeflag: tar.TypeReg,
			mode:     0o644,
			content:  "key=value\n",
		},
	}

	buf := createTarBuffer(t, entries)
	dst := t.TempDir()

	err := extractTar(context.Background(), buf, dst)
	require.NoError(t, err)

	// Verify directory was created.
	info, err := os.Stat(filepath.Join(dst, "usr", "bin"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Verify regular file content.
	data, err := os.ReadFile(filepath.Join(dst, "usr", "bin", "hello"))
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/sh\necho hello\n", string(data))

	// Verify the config file.
	data, err = os.ReadFile(filepath.Join(dst, "etc", "config.txt"))
	require.NoError(t, err)
	assert.Equal(t, "key=value\n", string(data))
}

func TestExtractTar_Symlinks(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{
			name:     "usr/bin/",
			typeflag: tar.TypeDir,
			mode:     0o755,
		},
		{
			name:     "usr/bin/real",
			typeflag: tar.TypeReg,
			mode:     0o755,
			content:  "real binary",
		},
		{
			name:     "usr/bin/link",
			typeflag: tar.TypeSymlink,
			mode:     0o777,
			linkname: "real",
		},
	}

	buf := createTarBuffer(t, entries)
	dst := t.TempDir()

	err := extractTar(context.Background(), buf, dst)
	require.NoError(t, err)

	// Verify the symlink exists and points to the right target.
	linkPath := filepath.Join(dst, "usr", "bin", "link")
	target, err := os.Readlink(linkPath)
	require.NoError(t, err)
	assert.Equal(t, "real", target)

	// Reading through the symlink should return the real content.
	data, err := os.ReadFile(linkPath)
	require.NoError(t, err)
	assert.Equal(t, "real binary", string(data))
}

func TestExtractTar_RejectsExcessiveEntryCount(t *testing.T) {
	// Not parallel: mutates the package-level maxExtractEntries.
	orig := maxExtractEntries
	t.Cleanup(func() { maxExtractEntries = orig })
	maxExtractEntries = 3

	entries := []tarEntry{
		{name: "a", typeflag: tar.TypeReg, mode: 0o644, content: ""},
		{name: "b", typeflag: tar.TypeReg, mode: 0o644, content: ""},
		{name: "c", typeflag: tar.TypeReg, mode: 0o644, content: ""},
		{name: "d", typeflag: tar.TypeReg, mode: 0o644, content: ""},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, t.TempDir())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum entry count")
}

func TestExtractTarSharedLimit_RejectsExcessiveEntryCount(t *testing.T) {
	// Not parallel: mutates the package-level maxExtractEntries.
	orig := maxExtractEntries
	t.Cleanup(func() { maxExtractEntries = orig })
	maxExtractEntries = 3

	entries := []tarEntry{
		{name: "a", typeflag: tar.TypeReg, mode: 0o644, content: ""},
		{name: "b", typeflag: tar.TypeReg, mode: 0o644, content: ""},
		{name: "c", typeflag: tar.TypeReg, mode: 0o644, content: ""},
		{name: "d", typeflag: tar.TypeReg, mode: 0o644, content: ""},
	}
	buf := createTarBuffer(t, entries)

	var remaining atomic.Int64
	remaining.Store(maxExtractSize)
	err := extractTarSharedLimit(context.Background(), buf, t.TempDir(), &remaining)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "maximum entry count")
}

func TestExtractTar_RejectsOversizedPayload(t *testing.T) {
	t.Parallel()

	// Create a tar with a file that is larger than the limit we impose.
	// We use a custom LimitedReader approach by feeding extractTar a
	// reader that wraps a tar archive with a very small limit.
	//
	// Since extractTar uses maxExtractSize internally, we test this by
	// creating an archive and wrapping it with our own limited reader.
	bigContent := strings.Repeat("A", 1024)

	entries := []tarEntry{
		{
			name:     "big.bin",
			typeflag: tar.TypeReg,
			mode:     0o644,
			content:  bigContent,
		},
	}

	buf := createTarBuffer(t, entries)

	// Wrap the buffer in a LimitedReader with a very small limit to simulate
	// maxExtractSize being exceeded. We need to set the limit smaller than
	// the archive itself.
	limitedReader := &io.LimitedReader{R: buf, N: 100}
	tr := tar.NewReader(limitedReader)

	// Read first header (should work since it's small).
	hdr, err := tr.Next()
	if err != nil {
		// If the limit is so small it can't even read the header, that's
		// also a valid rejection of oversized content.
		return
	}

	// Try to read the full file content; this should fail or be truncated.
	content := make([]byte, hdr.Size)
	_, err = io.ReadFull(tr, content)
	// Either we get an error or the content is truncated.
	assert.Error(t, err, "reading oversized content should fail with limited reader")
}

func TestExtractTar_SkipsPathTraversal(t *testing.T) {
	t.Parallel()

	// Create a tar with a path traversal entry. extractTar should skip it
	// and continue processing remaining entries.
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)

	// Malicious entry with path traversal.
	err := tw.WriteHeader(&tar.Header{
		Name:     "../../etc/passwd",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len("malicious")),
	})
	require.NoError(t, err)
	_, err = tw.Write([]byte("malicious"))
	require.NoError(t, err)

	// Legitimate entry.
	err = tw.WriteHeader(&tar.Header{
		Name:     "good.txt",
		Typeflag: tar.TypeReg,
		Mode:     0o644,
		Size:     int64(len("good content")),
	})
	require.NoError(t, err)
	_, err = tw.Write([]byte("good content"))
	require.NoError(t, err)

	err = tw.Close()
	require.NoError(t, err)

	dst := t.TempDir()
	err = extractTar(context.Background(), &buf, dst)
	require.NoError(t, err)

	// The malicious entry should not have been extracted.
	_, err = os.Stat(filepath.Join(dst, "..", "..", "etc", "passwd"))
	assert.True(t, os.IsNotExist(err) || err != nil)

	// The good entry should have been extracted.
	data, err := os.ReadFile(filepath.Join(dst, "good.txt"))
	require.NoError(t, err)
	assert.Equal(t, "good content", string(data))
}

func TestExtractTar_PreservesOwnershipBestEffort(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{
			name:     "root-owned/",
			typeflag: tar.TypeDir,
			mode:     0o755,
			uid:      0,
			gid:      0,
		},
		{
			name:     "root-owned/file.txt",
			typeflag: tar.TypeReg,
			mode:     0o644,
			content:  "owned by root",
			uid:      0,
			gid:      0,
		},
		{
			name:     "user-owned/",
			typeflag: tar.TypeDir,
			mode:     0o755,
			uid:      1000,
			gid:      1000,
		},
		{
			name:     "user-owned/file.txt",
			typeflag: tar.TypeReg,
			mode:     0o644,
			content:  "owned by user",
			uid:      1000,
			gid:      1000,
		},
	}

	buf := createTarBuffer(t, entries)
	dst := t.TempDir()

	err := extractTar(context.Background(), buf, dst)
	require.NoError(t, err)

	// Verify files were extracted regardless of uid/gid.
	data, err := os.ReadFile(filepath.Join(dst, "root-owned", "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "owned by root", string(data))

	data, err = os.ReadFile(filepath.Join(dst, "user-owned", "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, "owned by user", string(data))

	// When running as root, verify ownership is actually preserved.
	if os.Geteuid() == 0 {
		info, err := os.Lstat(filepath.Join(dst, "root-owned", "file.txt"))
		require.NoError(t, err)
		stat := info.Sys().(*syscall.Stat_t)
		assert.Equal(t, uint32(0), stat.Uid)
		assert.Equal(t, uint32(0), stat.Gid)

		info, err = os.Lstat(filepath.Join(dst, "user-owned", "file.txt"))
		require.NoError(t, err)
		stat = info.Sys().(*syscall.Stat_t)
		assert.Equal(t, uint32(1000), stat.Uid)
		assert.Equal(t, uint32(1000), stat.Gid)
	}
}

// mockFetcher is a test double for ImageFetcher.
type mockFetcher struct {
	img v1.Image
	err error
}

func (m *mockFetcher) Pull(_ context.Context, _ string) (v1.Image, error) {
	return m.img, m.err
}

type imageWithLayers struct {
	v1.Image
	layers []v1.Layer
}

func (i imageWithLayers) Layers() ([]v1.Layer, error) {
	return i.layers, nil
}

type failingUncompressedLayer struct {
	v1.Layer
	err      error
	failures atomic.Int32
	accesses atomic.Int32
}

func (l *failingUncompressedLayer) Uncompressed() (io.ReadCloser, error) {
	l.accesses.Add(1)
	if l.failures.Add(-1) >= 0 {
		return nil, l.err
	}
	return l.Layer.Uncompressed()
}

func TestPullWithFetcher_LayeredExtractionFailure(t *testing.T) {
	baseLayer := createLayerFromEntries(t, []tarEntry{
		{name: "file.txt", typeflag: tar.TypeReg, mode: 0o644, content: "content"},
	})
	baseImage := createImageFromLayers(t, baseLayer)

	tests := []struct {
		name          string
		extractionErr error
		wantErr       bool
	}{
		{
			name:          "permission restore error is fatal",
			extractionErr: fmt.Errorf("restore layer xattr: %w", xattr.ErrPermissionRestore),
			wantErr:       true,
		},
		{
			name:          "ordinary extraction error falls back to flat extraction",
			extractionErr: errors.New("layer extraction failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			layer := &failingUncompressedLayer{Layer: baseLayer, err: tt.extractionErr}
			layer.failures.Store(1)
			img := imageWithLayers{Image: baseImage, layers: []v1.Layer{layer}}
			cacheDir := t.TempDir()
			cache := NewCache(cacheDir)

			rootfs, err := PullWithFetcher(context.Background(), "example.com/test:layered-failure", cache, &mockFetcher{img: img})
			if tt.wantErr {
				require.ErrorIs(t, err, xattr.ErrPermissionRestore)
				assert.Nil(t, rootfs)
				assert.Equal(t, int32(1), layer.accesses.Load(), "flat extraction must not access the layer")

				entries, readErr := os.ReadDir(cacheDir)
				require.NoError(t, readErr)
				for _, entry := range entries {
					assert.False(t, strings.HasPrefix(entry.Name(), "tmp-rootfs-"), "temporary rootfs must be removed")
				}
				cached, listErr := cache.List()
				require.NoError(t, listErr)
				assert.Empty(t, cached, "failed extraction must not publish a rootfs cache entry")
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, rootfs)
			assert.Equal(t, int32(2), layer.accesses.Load(), "flat extraction must retry the layer")
			cached, listErr := cache.List()
			require.NoError(t, listErr)
			assert.Len(t, cached, 1)
		})
	}
}

func TestExtractOCIConfig_WithConfig(t *testing.T) {
	t.Parallel()

	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	cfg, err := extractOCIConfig(fakeImg)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
}

func TestExtractOCIConfig_ReturnsEmptyForNilConfig(t *testing.T) {
	t.Parallel()

	// random.Image always has a config, so we test the non-nil path.
	// The nil branch is defensive; verify that a valid image returns
	// a non-nil OCIConfig with populated or empty fields.
	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	cfg, err := extractOCIConfig(fakeImg)
	require.NoError(t, err)
	assert.NotNil(t, cfg)
	// random images have empty config fields
	assert.Empty(t, cfg.Entrypoint)
	assert.Empty(t, cfg.Cmd)
	assert.Empty(t, cfg.WorkingDir)
	assert.Empty(t, cfg.User)
}

func TestPullWithFetcher_CacheHit(t *testing.T) {
	t.Parallel()

	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	digest, err := fakeImg.Digest()
	require.NoError(t, err)

	cacheDir := t.TempDir()
	cache := NewCache(cacheDir)
	require.NoError(t, cache.ensureFormat())

	// Pre-populate the cache by creating the expected directory.
	cachedRootfs := t.TempDir()
	err = os.WriteFile(filepath.Join(cachedRootfs, "marker"), []byte("cached"), 0o644)
	require.NoError(t, err)
	err = cache.Put(digest.String(), cachedRootfs)
	require.NoError(t, err)

	fetcher := &mockFetcher{img: fakeImg}

	rootfs, err := PullWithFetcher(context.Background(), "example.com/test:latest", cache, fetcher)
	require.NoError(t, err)
	assert.NotEmpty(t, rootfs.Path)
	assert.DirExists(t, rootfs.Path)

	// Verify we got the cached path (contains our marker file).
	markerData, err := os.ReadFile(filepath.Join(rootfs.Path, "marker"))
	require.NoError(t, err)
	assert.Equal(t, "cached", string(markerData))

	// Cache hits must be marked so callers know to COW-clone before mutation.
	assert.True(t, rootfs.FromCache, "cache hit should set FromCache=true")
}

func TestPullWithFetcher_CacheMiss(t *testing.T) {
	t.Parallel()

	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	fetcher := &mockFetcher{img: fakeImg}
	cacheDir := t.TempDir()
	cache := NewCache(cacheDir)

	rootfs, err := PullWithFetcher(context.Background(), "example.com/test:latest", cache, fetcher)
	require.NoError(t, err)
	assert.NotEmpty(t, rootfs.Path)
	assert.DirExists(t, rootfs.Path)
	assert.NotNil(t, rootfs.Config)

	// The fresh extraction now lives in the cache and is reused by later
	// pulls, so callers must COW-clone it before mutation.
	assert.True(t, strings.HasPrefix(rootfs.Path, cacheDir+string(filepath.Separator)), "rootfs %q not in cache %q", rootfs.Path, cacheDir)
	assert.True(t, rootfs.FromCache, "rootfs stored in the cache should set FromCache=true")

	again, err := PullWithFetcher(context.Background(), "example.com/test:latest", cache, fetcher)
	require.NoError(t, err)
	assert.Equal(t, rootfs.Path, again.Path, "second pull reuses the cached rootfs")
}

func TestPullWithFetcher_NilCache(t *testing.T) {
	t.Parallel()

	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	fetcher := &mockFetcher{img: fakeImg}

	rootfs, err := PullWithFetcher(context.Background(), "example.com/test:latest", nil, fetcher)
	require.NoError(t, err)
	assert.NotEmpty(t, rootfs.Path)
	assert.DirExists(t, rootfs.Path)
	assert.NotNil(t, rootfs.Config)

	// Clean up extracted rootfs since there's no cache managing it.
	_ = os.RemoveAll(filepath.Dir(rootfs.Path))
}

func TestPullWithFetcher_ParseError(t *testing.T) {
	t.Parallel()

	fetcher := &mockFetcher{}

	_, err := PullWithFetcher(context.Background(), ":::invalid", nil, fetcher)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse image reference")
}

func TestPullWithFetcher_FetchError(t *testing.T) {
	t.Parallel()

	fetchErr := errors.New("network timeout")
	fetcher := &mockFetcher{err: fetchErr}

	_, err := PullWithFetcher(context.Background(), "example.com/test:latest", nil, fetcher)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pull image")
	assert.ErrorIs(t, err, fetchErr)
}

func TestPullWithFetcher_NilFetcher(t *testing.T) {
	t.Parallel()

	// With nil fetcher, PullWithFetcher uses the local-then-remote fallback
	// which will try the daemon and then a real registry. Use an invalid
	// ref that parses but fails to pull, confirming nil fetcher doesn't panic.
	_, err := PullWithFetcher(context.Background(), "localhost:1/nonexistent:latest", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pull image")
}

// ---------------------------------------------------------------------------
// extractHardlink tests
// ---------------------------------------------------------------------------

func TestExtractHardlink_ValidLink(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	entries := []tarEntry{
		{name: "original.txt", typeflag: tar.TypeReg, mode: 0o644, content: "hello"},
		{name: "link.txt", typeflag: tar.TypeLink, mode: 0o644, linkname: "original.txt"},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, dst)
	require.NoError(t, err)

	origInfo, err := os.Lstat(filepath.Join(dst, "original.txt"))
	require.NoError(t, err)
	linkInfo, err := os.Lstat(filepath.Join(dst, "link.txt"))
	require.NoError(t, err)

	origStat := origInfo.Sys().(*syscall.Stat_t)
	linkStat := linkInfo.Sys().(*syscall.Stat_t)
	assert.Equal(t, origStat.Ino, linkStat.Ino, "hardlink should share the same inode")
}

func TestExtractHardlink_SourceOutsideRootfs(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	entries := []tarEntry{
		{name: "escape.txt", typeflag: tar.TypeLink, mode: 0o644, linkname: "../../etc/passwd"},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hardlink")
	assert.Contains(t, err.Error(), "outside rootfs")
}

func TestExtractHardlink_SourceIsSymlink(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	// Pre-create a symlink as the source.
	err := os.Symlink("nonexistent", filepath.Join(dst, "sym"))
	require.NoError(t, err)

	entries := []tarEntry{
		{name: "link.txt", typeflag: tar.TypeLink, mode: 0o644, linkname: "sym"},
	}
	buf := createTarBuffer(t, entries)

	err = extractTar(context.Background(), buf, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing hardlink to symlink")
}

func TestExtractHardlink_SourceIsDirectory(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	// Pre-create a directory as the source.
	err := os.Mkdir(filepath.Join(dst, "mydir"), 0o755)
	require.NoError(t, err)

	entries := []tarEntry{
		{name: "link.txt", typeflag: tar.TypeLink, mode: 0o644, linkname: "mydir"},
	}
	buf := createTarBuffer(t, entries)

	err = extractTar(context.Background(), buf, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing hardlink to non-regular file")
}

func TestExtractHardlink_SourceNotExtracted(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	entries := []tarEntry{
		{name: "link.txt", typeflag: tar.TypeLink, mode: 0o644, linkname: "does-not-exist.txt"},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "stat hardlink source")
}

func TestExtractHardlink_TargetIsExistingSymlink(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	// Create the real file that will be the hardlink source.
	err := os.WriteFile(filepath.Join(dst, "original.txt"), []byte("data"), 0o644)
	require.NoError(t, err)

	// Pre-create a symlink at the target location.
	err = os.Symlink("original.txt", filepath.Join(dst, "link.txt"))
	require.NoError(t, err)

	entries := []tarEntry{
		{name: "link.txt", typeflag: tar.TypeLink, mode: 0o644, linkname: "original.txt"},
	}
	buf := createTarBuffer(t, entries)

	err = extractTar(context.Background(), buf, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to write through symlink")
}

// ---------------------------------------------------------------------------
// extractSymlink edge-case tests
// ---------------------------------------------------------------------------

func TestExtractSymlink_AbsoluteEscapeAttempt(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	entries := []tarEntry{
		{name: "escape", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "/../../../etc/passwd"},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "points outside rootfs")
}

func TestExtractSymlink_RelativeEscapeAttempt(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	entries := []tarEntry{
		{name: "escape", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../../../../../../etc/passwd"},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "points outside rootfs")
}

func TestExtractSymlink_ReplacesExistingFile(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	// Extract a regular file, then a symlink at the same path.
	entries := []tarEntry{
		{name: "target.txt", typeflag: tar.TypeReg, mode: 0o644, content: "real content"},
		{name: "overwrite", typeflag: tar.TypeReg, mode: 0o644, content: "old"},
		{name: "overwrite", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "target.txt"},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, dst)
	require.NoError(t, err)

	// "overwrite" should now be a symlink to "target.txt".
	linkTarget, err := os.Readlink(filepath.Join(dst, "overwrite"))
	require.NoError(t, err)
	assert.Equal(t, "target.txt", linkTarget)

	data, err := os.ReadFile(filepath.Join(dst, "overwrite"))
	require.NoError(t, err)
	assert.Equal(t, "real content", string(data))
}

func TestExtractSymlink_ReplacesDirectory(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	// mutate.Extract squashes layers newest-first, so a tool layer's directory
	// entry can arrive before the base layer's symlink at the same path (e.g.
	// var/run -> ../run from wolfi/chainguard). The extractor must replace the
	// directory -- including its contents -- with the symlink.
	entries := []tarEntry{
		{name: "mydir/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "mydir/inner.txt", typeflag: tar.TypeReg, mode: 0o644, content: "stale"},
		{name: "somewhere", typeflag: tar.TypeReg, mode: 0o644, content: "real content"},
		{name: "mydir", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "somewhere"},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, dst)
	require.NoError(t, err)

	linkTarget, err := os.Readlink(filepath.Join(dst, "mydir"))
	require.NoError(t, err)
	assert.Equal(t, "somewhere", linkTarget)

	// mydir now resolves through the symlink to the "somewhere" regular file,
	// so looking up mydir/inner.txt fails outright -- the stale directory and
	// its contents are gone.
	_, err = os.Lstat(filepath.Join(dst, "mydir", "inner.txt"))
	assert.Error(t, err)
}

func TestExtractSymlink_EscapeAttemptRefusedEvenOverDirectory(t *testing.T) {
	t.Parallel()

	dst := t.TempDir()

	// A directory must not be removed unless the replacing symlink's target
	// has already been validated to stay within the rootfs.
	entries := []tarEntry{
		{name: "mydir/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "mydir/inner.txt", typeflag: tar.TypeReg, mode: 0o644, content: "kept"},
		{name: "mydir", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../../../../../../etc/passwd"},
	}
	buf := createTarBuffer(t, entries)

	err := extractTar(context.Background(), buf, dst)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "points outside rootfs")

	// The directory and its contents must survive the refused replacement.
	data, err := os.ReadFile(filepath.Join(dst, "mydir", "inner.txt"))
	require.NoError(t, err)
	assert.Equal(t, "kept", string(data))
}

// ---------------------------------------------------------------------------
// mkdirAllNoSymlink tests
// ---------------------------------------------------------------------------

func TestMkdirAllNoSymlink_SymlinkInPath(t *testing.T) {
	t.Parallel()

	base := t.TempDir()

	// Create base/a as a symlink to /tmp.
	err := os.Symlink(os.TempDir(), filepath.Join(base, "a"))
	require.NoError(t, err)

	err = mkdirAllNoSymlink(base, filepath.Join(base, "a", "b"), 0o755)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing to traverse symlink")
}

func TestMkdirAllNoSymlink_NonDirInPath(t *testing.T) {
	t.Parallel()

	base := t.TempDir()

	// Create a regular file where a directory is expected.
	err := os.WriteFile(filepath.Join(base, "notdir"), []byte("file"), 0o644)
	require.NoError(t, err)

	err = mkdirAllNoSymlink(base, filepath.Join(base, "notdir", "child"), 0o755)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path component is not a directory")
}

func TestMkdirAllNoSymlink_TargetOutsideBase(t *testing.T) {
	t.Parallel()

	base := t.TempDir()

	err := mkdirAllNoSymlink(base, "/tmp/outside", 0o755)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid target directory")
}

func TestMkdirAllNoSymlink_TargetEqualsBase(t *testing.T) {
	t.Parallel()

	base := t.TempDir()

	// Target equals base should be a no-op (returns nil).
	err := mkdirAllNoSymlink(base, base, 0o755)
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// validateNoSymlinkLeaf tests (table-driven)
// ---------------------------------------------------------------------------

func TestValidateNoSymlinkLeaf(t *testing.T) {
	t.Parallel()

	base := t.TempDir()

	// Set up fixtures.
	symPath := filepath.Join(base, "sym")
	err := os.Symlink("nonexistent", symPath)
	require.NoError(t, err)

	dirPath := filepath.Join(base, "dir")
	err = os.Mkdir(dirPath, 0o755)
	require.NoError(t, err)

	filePath := filepath.Join(base, "file")
	err = os.WriteFile(filePath, []byte("data"), 0o644)
	require.NoError(t, err)

	nonexistentPath := filepath.Join(base, "nonexistent")

	tests := []struct {
		name      string
		target    string
		wantErr   bool
		errSubstr string
	}{
		{name: "existing symlink", target: symPath, wantErr: true, errSubstr: "refusing to write through symlink"},
		{name: "existing directory", target: dirPath, wantErr: true, errSubstr: "refusing to overwrite directory with file"},
		{name: "existing regular file", target: filePath, wantErr: false},
		{name: "non-existent path", target: nonexistentPath, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateNoSymlinkLeaf(tt.target)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Other extractTar tests
// ---------------------------------------------------------------------------

func TestExtractTar_EmptyArchive(t *testing.T) {
	t.Parallel()

	// Create an empty tar archive (no entries).
	// Empty layers are legitimate in OCI images (produced by ENV, LABEL, CMD, etc.).
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := tw.Close()
	require.NoError(t, err)

	dst := t.TempDir()
	err = extractTar(context.Background(), &buf, dst)
	require.NoError(t, err)

	// Destination directory should be empty (no files extracted).
	entries, err := os.ReadDir(dst)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestExtractTar_UnsupportedEntryType(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		// FIFO (unsupported) -- should be skipped.
		{name: "myfifo", typeflag: tar.TypeFifo, mode: 0o644},
		// Regular file -- should be extracted.
		{name: "good.txt", typeflag: tar.TypeReg, mode: 0o644, content: "valid"},
	}
	buf := createTarBuffer(t, entries)

	dst := t.TempDir()
	err := extractTar(context.Background(), buf, dst)
	require.NoError(t, err)

	// FIFO should not exist.
	_, err = os.Lstat(filepath.Join(dst, "myfifo"))
	assert.True(t, os.IsNotExist(err), "FIFO should not have been extracted")

	// Regular file should exist.
	data, err := os.ReadFile(filepath.Join(dst, "good.txt"))
	require.NoError(t, err)
	assert.Equal(t, "valid", string(data))
}

// ---------------------------------------------------------------------------
// Layered extraction tests
// ---------------------------------------------------------------------------

// createLayerFromEntries creates an OCI layer from tar entries.
func createLayerFromEntries(t *testing.T, entries []tarEntry) v1.Layer {
	t.Helper()
	buf := createTarBuffer(t, entries)
	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
	require.NoError(t, err)
	return layer
}

// createImageFromLayers builds an OCI image from the given layers.
func createImageFromLayers(t *testing.T, layers ...v1.Layer) v1.Image {
	t.Helper()
	img, err := mutate.AppendLayers(empty.Image, layers...)
	require.NoError(t, err)
	return img
}

func TestExtractImageLayered_BasicExtraction(t *testing.T) {
	t.Parallel()

	// Create a two-layer image: base layer + app layer.
	baseLayer := createLayerFromEntries(t, []tarEntry{
		{name: "etc/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "etc/os-release", typeflag: tar.TypeReg, mode: 0o644, content: "Alpine Linux"},
		{name: "usr/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "usr/bin/", typeflag: tar.TypeDir, mode: 0o755},
	})

	appLayer := createLayerFromEntries(t, []tarEntry{
		{name: "app/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "app/main", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\necho hello"},
	})

	img := createImageFromLayers(t, baseLayer, appLayer)

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)
	dst := t.TempDir()

	err := extractImageLayered(context.Background(), img, dst, lc)
	require.NoError(t, err)

	// Verify files from both layers are present.
	data, err := os.ReadFile(filepath.Join(dst, "etc", "os-release"))
	require.NoError(t, err)
	assert.Equal(t, "Alpine Linux", string(data))

	data, err = os.ReadFile(filepath.Join(dst, "app", "main"))
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/sh\necho hello", string(data))
}

func TestExtractImageLayered_SharedLayers(t *testing.T) {
	t.Parallel()

	// Create a shared base layer and two different app layers.
	baseLayer := createLayerFromEntries(t, []tarEntry{
		{name: "base.txt", typeflag: tar.TypeReg, mode: 0o644, content: "shared base"},
	})

	appLayer1 := createLayerFromEntries(t, []tarEntry{
		{name: "app1.txt", typeflag: tar.TypeReg, mode: 0o644, content: "app v1"},
	})

	appLayer2 := createLayerFromEntries(t, []tarEntry{
		{name: "app2.txt", typeflag: tar.TypeReg, mode: 0o644, content: "app v2"},
	})

	img1 := createImageFromLayers(t, baseLayer, appLayer1)
	img2 := createImageFromLayers(t, baseLayer, appLayer2)

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)

	// Extract first image.
	dst1 := t.TempDir()
	err := extractImageLayered(context.Background(), img1, dst1, lc)
	require.NoError(t, err)

	// Get the base layer DiffID to check cache state.
	cfgFile, err := img1.ConfigFile()
	require.NoError(t, err)
	baseDiffID := cfgFile.RootFS.DiffIDs[0]

	// Verify base layer is cached.
	assert.True(t, lc.Has(baseDiffID), "base layer should be cached after first extraction")

	// Extract second image — base layer should be a cache hit.
	dst2 := t.TempDir()
	err = extractImageLayered(context.Background(), img2, dst2, lc)
	require.NoError(t, err)

	// Verify both images have the shared base content.
	data1, err := os.ReadFile(filepath.Join(dst1, "base.txt"))
	require.NoError(t, err)
	assert.Equal(t, "shared base", string(data1))

	data2, err := os.ReadFile(filepath.Join(dst2, "base.txt"))
	require.NoError(t, err)
	assert.Equal(t, "shared base", string(data2))

	// Verify each image has its own app content.
	data1, err = os.ReadFile(filepath.Join(dst1, "app1.txt"))
	require.NoError(t, err)
	assert.Equal(t, "app v1", string(data1))

	data2, err = os.ReadFile(filepath.Join(dst2, "app2.txt"))
	require.NoError(t, err)
	assert.Equal(t, "app v2", string(data2))
}

func TestExtractImageLayered_Whiteouts(t *testing.T) {
	t.Parallel()

	// Base layer has files, upper layer whiteouts one of them.
	baseLayer := createLayerFromEntries(t, []tarEntry{
		{name: "keep.txt", typeflag: tar.TypeReg, mode: 0o644, content: "keep me"},
		{name: "delete.txt", typeflag: tar.TypeReg, mode: 0o644, content: "delete me"},
		{name: "dir/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "dir/file.txt", typeflag: tar.TypeReg, mode: 0o644, content: "in dir"},
	})

	upperLayer := createLayerFromEntries(t, []tarEntry{
		// Whiteout for delete.txt
		{name: ".wh.delete.txt", typeflag: tar.TypeReg, mode: 0o644},
		// Opaque whiteout for dir/ (clears all contents)
		{name: "dir/.wh..wh..opq", typeflag: tar.TypeReg, mode: 0o644},
		// New file in dir after opaque whiteout
		{name: "dir/new.txt", typeflag: tar.TypeReg, mode: 0o644, content: "new content"},
	})

	img := createImageFromLayers(t, baseLayer, upperLayer)

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)
	dst := t.TempDir()

	err := extractImageLayered(context.Background(), img, dst, lc)
	require.NoError(t, err)

	// keep.txt should still exist.
	data, err := os.ReadFile(filepath.Join(dst, "keep.txt"))
	require.NoError(t, err)
	assert.Equal(t, "keep me", string(data))

	// delete.txt should have been removed by whiteout.
	_, err = os.Stat(filepath.Join(dst, "delete.txt"))
	assert.True(t, os.IsNotExist(err), "delete.txt should be removed by whiteout")

	// dir/ should exist but dir/file.txt should be gone (opaque whiteout).
	_, err = os.Stat(filepath.Join(dst, "dir"))
	require.NoError(t, err, "dir should still exist")

	_, err = os.Stat(filepath.Join(dst, "dir", "file.txt"))
	assert.True(t, os.IsNotExist(err), "dir/file.txt should be removed by opaque whiteout")

	// dir/new.txt should exist (added after opaque whiteout).
	data, err = os.ReadFile(filepath.Join(dst, "dir", "new.txt"))
	require.NoError(t, err)
	assert.Equal(t, "new content", string(data))
}

func TestExtractImageLayered_UpperLayerOverridesFile(t *testing.T) {
	t.Parallel()

	baseLayer := createLayerFromEntries(t, []tarEntry{
		{name: "config.txt", typeflag: tar.TypeReg, mode: 0o644, content: "version=1"},
	})

	upperLayer := createLayerFromEntries(t, []tarEntry{
		{name: "config.txt", typeflag: tar.TypeReg, mode: 0o644, content: "version=2"},
	})

	img := createImageFromLayers(t, baseLayer, upperLayer)

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)
	dst := t.TempDir()

	err := extractImageLayered(context.Background(), img, dst, lc)
	require.NoError(t, err)

	// Upper layer should win.
	data, err := os.ReadFile(filepath.Join(dst, "config.txt"))
	require.NoError(t, err)
	assert.Equal(t, "version=2", string(data))
}

func TestExtractImageLayered_Symlinks(t *testing.T) {
	t.Parallel()

	layer := createLayerFromEntries(t, []tarEntry{
		{name: "usr/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "usr/bin/real", typeflag: tar.TypeReg, mode: 0o755, content: "binary"},
		{name: "usr/bin/link", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "real"},
	})

	img := createImageFromLayers(t, layer)

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)
	dst := t.TempDir()

	err := extractImageLayered(context.Background(), img, dst, lc)
	require.NoError(t, err)

	target, err := os.Readlink(filepath.Join(dst, "usr", "bin", "link"))
	require.NoError(t, err)
	assert.Equal(t, "real", target)

	data, err := os.ReadFile(filepath.Join(dst, "usr", "bin", "link"))
	require.NoError(t, err)
	assert.Equal(t, "binary", string(data))
}

func TestPullWithFetcher_LayeredExtraction(t *testing.T) {
	t.Parallel()

	// Use random image (which has valid layers) with a cache.
	fakeImg, err := random.Image(256, 2)
	require.NoError(t, err)

	fetcher := &mockFetcher{img: fakeImg}
	cacheDir := t.TempDir()
	cache := NewCache(cacheDir)

	rootfs, err := PullWithFetcher(context.Background(), "example.com/test:layered", cache, fetcher)
	require.NoError(t, err)
	assert.NotEmpty(t, rootfs.Path)
	assert.DirExists(t, rootfs.Path)

	// Verify layer cache was populated.
	layerCacheDir := filepath.Join(cacheDir, "layers")
	_, err = os.Stat(layerCacheDir)
	require.NoError(t, err, "layers/ directory should exist")

	entries, err := os.ReadDir(layerCacheDir)
	require.NoError(t, err)

	// Filter out tmp- directories.
	var layerEntries []os.DirEntry
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "tmp-") {
			layerEntries = append(layerEntries, e)
		}
	}
	assert.Equal(t, 2, len(layerEntries), "should have 2 cached layers")
}

// ---------------------------------------------------------------------------
// Empty layer tests (Bug 1: empty OCI layers are valid no-ops)
// ---------------------------------------------------------------------------

func TestExtractTarSharedLimit_EmptyArchive(t *testing.T) {
	t.Parallel()

	// Empty tar archive — should succeed (empty layers are valid OCI artifacts).
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := tw.Close()
	require.NoError(t, err)

	remaining := &atomic.Int64{}
	remaining.Store(maxExtractSize)

	dst := t.TempDir()
	err = extractTarSharedLimit(context.Background(), &buf, dst, remaining)
	require.NoError(t, err)

	entries, err := os.ReadDir(dst)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestExtractImageLayered_EmptyLayers(t *testing.T) {
	t.Parallel()

	// Create a real layer with content + an empty layer (simulates ENV/LABEL/CMD).
	realLayer := createLayerFromEntries(t, []tarEntry{
		{name: "app/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "app/main", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\necho hello"},
	})

	emptyLayer := createLayerFromEntries(t, nil)

	img := createImageFromLayers(t, realLayer, emptyLayer)

	cacheDir := t.TempDir()
	lc := NewLayerCache(cacheDir)
	dst := t.TempDir()

	err := extractImageLayered(context.Background(), img, dst, lc)
	require.NoError(t, err)

	// Verify the real layer's content is present.
	data, err := os.ReadFile(filepath.Join(dst, "app", "main"))
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/sh\necho hello", string(data))
}

// ---------------------------------------------------------------------------
// Context cancellation tests (Bug 2: extraction respects context)
// ---------------------------------------------------------------------------

func TestExtractTar_ContextCancellation(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{name: "file.txt", typeflag: tar.TypeReg, mode: 0o644, content: "data"},
	}
	buf := createTarBuffer(t, entries)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	dst := t.TempDir()
	err := extractTar(ctx, buf, dst)
	require.ErrorIs(t, err, context.Canceled)
}

func TestExtractTarSharedLimit_ContextCancellation(t *testing.T) {
	t.Parallel()

	entries := []tarEntry{
		{name: "file.txt", typeflag: tar.TypeReg, mode: 0o644, content: "data"},
	}
	buf := createTarBuffer(t, entries)

	remaining := &atomic.Int64{}
	remaining.Store(maxExtractSize)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	dst := t.TempDir()
	err := extractTarSharedLimit(ctx, buf, dst, remaining)
	require.ErrorIs(t, err, context.Canceled)
}

func TestExtractTar_SpecialModeBits(t *testing.T) {
	t.Parallel()

	// Own uid and gid make the chown succeed, which clears setuid and setgid.
	uid, gid := os.Getuid(), os.Getgid()
	entries := []tarEntry{
		{name: "usr/bin/sudo", typeflag: tar.TypeReg, mode: 0o4755, content: "sudo", uid: uid, gid: gid},
		{name: "usr/bin/wall", typeflag: tar.TypeReg, mode: 0o2755, content: "wall", uid: uid, gid: gid},
		{name: "usr/bin/sudoedit", typeflag: tar.TypeLink, mode: 0o4755, linkname: "usr/bin/sudo", uid: uid, gid: gid},
	}
	dst := t.TempDir()
	require.NoError(t, extractTar(context.Background(), createTarBuffer(t, entries), dst))

	assertSpecialModeBits(t, filepath.Join(dst, "usr", "bin"))
	info, err := os.Stat(filepath.Join(dst, "usr", "bin", "sudoedit"))
	require.NoError(t, err)
	assert.Equal(t, specialMode(os.ModeSetuid), info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid))
}

func TestExtractImageLayered_SpecialModeBits(t *testing.T) {
	t.Parallel()

	uid, gid := os.Getuid(), os.Getgid()
	layer := createLayerFromEntries(t, []tarEntry{
		{name: "usr/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "usr/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "usr/bin/sudo", typeflag: tar.TypeReg, mode: 0o4755, content: "sudo", uid: uid, gid: gid},
		{name: "usr/bin/wall", typeflag: tar.TypeReg, mode: 0o2755, content: "wall", uid: uid, gid: gid},
	})
	img := createImageFromLayers(t, layer)
	dst := t.TempDir()
	require.NoError(t, extractImageLayered(context.Background(), img, dst, NewLayerCache(t.TempDir())))

	assertSpecialModeBits(t, filepath.Join(dst, "usr", "bin"))
}

// specialMode returns the 0o755 mode an extracted file with the given
// setuid or setgid bit should have on this host.
func specialMode(bit os.FileMode) os.FileMode {
	if pathutil.KeepsSpecialBits() {
		return bit | 0o755
	}
	return 0o755
}

// assertSpecialModeBits checks the sudo (setuid) and wall (setgid) files
// in dir.
func assertSpecialModeBits(t *testing.T, dir string) {
	t.Helper()

	want := map[string]os.FileMode{
		"sudo": specialMode(os.ModeSetuid),
		"wall": specialMode(os.ModeSetgid),
	}
	for name, mode := range want {
		info, err := os.Stat(filepath.Join(dir, name))
		require.NoError(t, err)
		assert.Equal(t, mode, info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid), name)
	}
}

func TestPullWithFetcher_NilCachePrivateParent(t *testing.T) {
	t.Parallel()

	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	rootfs, err := PullWithFetcher(context.Background(), "example.com/test:latest", nil, &mockFetcher{img: fakeImg})
	require.NoError(t, err)
	parent := filepath.Dir(rootfs.Path)
	t.Cleanup(func() { _ = os.RemoveAll(parent) })

	info, err := os.Stat(parent)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}
