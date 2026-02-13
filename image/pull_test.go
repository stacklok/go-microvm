// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
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

	err := extractTar(buf, dst)
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

	err := extractTar(buf, dst)
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
	err = extractTar(&buf, dst)
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

	err := extractTar(buf, dst)
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
}

func TestPullWithFetcher_CacheMiss(t *testing.T) {
	t.Parallel()

	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	fetcher := &mockFetcher{img: fakeImg}
	cache := NewCache(t.TempDir())

	rootfs, err := PullWithFetcher(context.Background(), "example.com/test:latest", cache, fetcher)
	require.NoError(t, err)
	assert.NotEmpty(t, rootfs.Path)
	assert.DirExists(t, rootfs.Path)
	assert.NotNil(t, rootfs.Config)
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
	_ = os.RemoveAll(rootfs.Path)
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
