// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package disk

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetch_Success(t *testing.T) {
	t.Parallel()

	content := []byte("hello disk image")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	url := srv.URL + "/image.raw"

	path, err := Fetch(context.Background(), url, cacheDir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(cacheDir, "image.raw"), path)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestFetch_ChecksumMatch(t *testing.T) {
	t.Parallel()

	content := []byte("checksum verified content")
	h := sha256.Sum256(content)
	checksum := hex.EncodeToString(h[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	url := srv.URL + "/verified.bin"

	path, err := Fetch(context.Background(), url, cacheDir, WithChecksum(checksum))
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, data)
}

func TestFetch_ChecksumMismatch(t *testing.T) {
	t.Parallel()

	content := []byte("real content")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	url := srv.URL + "/bad.bin"

	_, err := Fetch(context.Background(), url, cacheDir,
		WithChecksum("0000000000000000000000000000000000000000000000000000000000000000"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "checksum mismatch")

	// The file should have been removed after checksum failure.
	_, statErr := os.Stat(filepath.Join(cacheDir, "bad.bin"))
	assert.True(t, os.IsNotExist(statErr))
}

func TestFetch_Retry(t *testing.T) {
	t.Parallel()

	content := []byte("retry success")
	var attempts atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	url := srv.URL + "/retried.bin"

	path, err := Fetch(context.Background(), url, cacheDir)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, content, data)
	assert.GreaterOrEqual(t, int(attempts.Load()), 2)
}

func TestFetch_ContextCancellation(t *testing.T) {
	t.Parallel()

	// Create a server that blocks until the context is cancelled.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	cacheDir := t.TempDir()
	url := srv.URL + "/blocked.bin"

	_, err := Fetch(ctx, url, cacheDir)
	require.Error(t, err)
}

func TestFetch_CacheHit(t *testing.T) {
	t.Parallel()

	content := []byte("cached content")
	var requestCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requestCount.Add(1)
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	url := srv.URL + "/cached.bin"

	// First fetch downloads the file.
	path1, err := Fetch(context.Background(), url, cacheDir)
	require.NoError(t, err)
	assert.Equal(t, int32(1), requestCount.Load())

	// Second fetch uses the cache; no additional HTTP request.
	path2, err := Fetch(context.Background(), url, cacheDir)
	require.NoError(t, err)
	assert.Equal(t, path1, path2)
	assert.Equal(t, int32(1), requestCount.Load())

	data, err := os.ReadFile(path2)
	require.NoError(t, err)
	assert.Equal(t, content, data)
}
