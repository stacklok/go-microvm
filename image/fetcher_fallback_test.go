// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFallbackFetcher_FirstSucceeds(t *testing.T) {
	t.Parallel()

	img, err := random.Image(256, 1)
	require.NoError(t, err)

	f := NewFallbackFetcher(
		&mockFetcher{img: img},
		&mockFetcher{err: errors.New("should not be called")},
	)

	got, err := f.Pull(context.Background(), "example.com/test:latest")
	require.NoError(t, err)
	assert.Equal(t, img, got)
}

func TestFallbackFetcher_FirstFailsSecondSucceeds(t *testing.T) {
	t.Parallel()

	img, err := random.Image(256, 1)
	require.NoError(t, err)

	f := NewFallbackFetcher(
		&mockFetcher{err: errors.New("daemon not available")},
		&mockFetcher{img: img},
	)

	got, err := f.Pull(context.Background(), "example.com/test:latest")
	require.NoError(t, err)
	assert.Equal(t, img, got)
}

func TestFallbackFetcher_AllFail(t *testing.T) {
	t.Parallel()

	err1 := errors.New("daemon error")
	err2 := errors.New("registry error")

	f := NewFallbackFetcher(
		&mockFetcher{err: err1},
		&mockFetcher{err: err2},
	)

	_, err := f.Pull(context.Background(), "example.com/test:latest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all fetchers failed")
	assert.ErrorIs(t, err, err1)
	assert.ErrorIs(t, err, err2)
}

func TestFallbackFetcher_SingleFetcher(t *testing.T) {
	t.Parallel()

	img, err := random.Image(256, 1)
	require.NoError(t, err)

	f := NewFallbackFetcher(&mockFetcher{img: img})

	got, err := f.Pull(context.Background(), "example.com/test:latest")
	require.NoError(t, err)
	assert.Equal(t, img, got)
}

func TestFallbackFetcher_ZeroFetchers(t *testing.T) {
	t.Parallel()

	f := NewFallbackFetcher()

	_, err := f.Pull(context.Background(), "example.com/test:latest")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no fetchers configured")
}

func TestFallbackFetcher_ThreeFetchers(t *testing.T) {
	t.Parallel()

	img, err := random.Image(256, 1)
	require.NoError(t, err)

	f := NewFallbackFetcher(
		&mockFetcher{err: errors.New("first fail")},
		&mockFetcher{err: errors.New("second fail")},
		&mockFetcher{img: img},
	)

	got, err := f.Pull(context.Background(), "example.com/test:latest")
	require.NoError(t, err)
	assert.Equal(t, img, got)
}

func TestNewLocalThenRemoteFetcher(t *testing.T) {
	t.Parallel()

	f := NewLocalThenRemoteFetcher()
	require.Len(t, f.fetchers, 2)

	// Verify the fetcher types.
	_, isDaemon := f.fetchers[0].(DaemonFetcher)
	assert.True(t, isDaemon, "first fetcher should be DaemonFetcher")

	_, isRemote := f.fetchers[1].(RemoteFetcher)
	assert.True(t, isRemote, "second fetcher should be RemoteFetcher")
}

// Verify FallbackFetcher implements ImageFetcher.
var _ ImageFetcher = (*FallbackFetcher)(nil)

// Verify concrete fetchers implement ImageFetcher.
var _ ImageFetcher = RemoteFetcher{}
var _ ImageFetcher = DaemonFetcher{}

// Verify the mockFetcher compiles as ImageFetcher (it's defined in pull_test.go).
var _ ImageFetcher = (*mockFetcher)(nil)
