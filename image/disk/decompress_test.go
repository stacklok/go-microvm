// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createZstdTar creates a zstd-compressed tar archive from the provided entries.
func createZstdTar(t *testing.T, entries []testTarEntry) *bytes.Buffer {
	t.Helper()

	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)

	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     e.mode,
			Size:     int64(len(e.content)),
			Linkname: e.linkname,
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

	// Compress with zstd.
	var zstdBuf bytes.Buffer
	enc, err := zstd.NewWriter(&zstdBuf)
	require.NoError(t, err)

	_, err = enc.Write(tarBuf.Bytes())
	require.NoError(t, err)

	err = enc.Close()
	require.NoError(t, err)

	return &zstdBuf
}

type testTarEntry struct {
	name     string
	typeflag byte
	mode     int64
	content  string
	linkname string
}

func TestDecompress_ZstdTar(t *testing.T) {
	t.Parallel()

	entries := []testTarEntry{
		{name: "dir/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "dir/hello.txt", typeflag: tar.TypeReg, mode: 0o644, content: "hello world"},
		{name: "dir/script.sh", typeflag: tar.TypeReg, mode: 0o755, content: "#!/bin/sh\necho hi\n"},
	}

	buf := createZstdTar(t, entries)
	destDir := t.TempDir()

	err := Decompress(context.Background(), buf, destDir)
	require.NoError(t, err)

	// Verify directory.
	info, err := os.Stat(filepath.Join(destDir, "dir"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	// Verify file contents.
	data, err := os.ReadFile(filepath.Join(destDir, "dir", "hello.txt"))
	require.NoError(t, err)
	assert.Equal(t, "hello world", string(data))

	data, err = os.ReadFile(filepath.Join(destDir, "dir", "script.sh"))
	require.NoError(t, err)
	assert.Equal(t, "#!/bin/sh\necho hi\n", string(data))
}

func TestDecompress_StripsAbsolutePaths(t *testing.T) {
	t.Parallel()

	entries := []testTarEntry{
		// An absolute path entry — the leading "/" should be stripped and
		// the file extracted safely under destDir (standard tar behavior).
		{name: "/etc/passwd", typeflag: tar.TypeReg, mode: 0o644, content: "root:x:0:0"},
		{name: "good.txt", typeflag: tar.TypeReg, mode: 0o644, content: "safe"},
	}

	buf := createZstdTar(t, entries)
	destDir := t.TempDir()

	err := Decompress(context.Background(), buf, destDir)
	require.NoError(t, err)

	// The absolute path entry should be extracted under destDir with the "/" stripped.
	data, err := os.ReadFile(filepath.Join(destDir, "etc", "passwd"))
	require.NoError(t, err)
	assert.Equal(t, "root:x:0:0", string(data))

	// The good entry should also be extracted.
	data, err = os.ReadFile(filepath.Join(destDir, "good.txt"))
	require.NoError(t, err)
	assert.Equal(t, "safe", string(data))
}

func TestDecompress_RejectsSymlinkTraversal(t *testing.T) {
	t.Parallel()

	entries := []testTarEntry{
		{name: "escape", typeflag: tar.TypeSymlink, mode: 0o777, linkname: "../../../../../../etc/passwd"},
	}

	buf := createZstdTar(t, entries)
	destDir := t.TempDir()

	err := Decompress(context.Background(), buf, destDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "points outside root")
}

func TestDecompress_EmptyArchive(t *testing.T) {
	t.Parallel()

	// Create a zstd-compressed tar with no entries.
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	err := tw.Close()
	require.NoError(t, err)

	var zstdBuf bytes.Buffer
	enc, err := zstd.NewWriter(&zstdBuf)
	require.NoError(t, err)

	_, err = enc.Write(tarBuf.Bytes())
	require.NoError(t, err)

	err = enc.Close()
	require.NoError(t, err)

	destDir := t.TempDir()

	err = Decompress(context.Background(), &zstdBuf, destDir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty or contains no valid entries")
}
