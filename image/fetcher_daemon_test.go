// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDaemonFetcher_InvalidReference(t *testing.T) {
	t.Parallel()

	f := DaemonFetcher{}
	_, err := f.Pull(context.Background(), ":::invalid")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse reference")
}

func TestDaemonFetcher_NoDaemon(t *testing.T) {
	t.Parallel()

	// When no Docker/Podman daemon is running, Pull should return a
	// graceful error (not panic). The exact error depends on the
	// environment but it should not be nil.
	f := DaemonFetcher{}
	_, err := f.Pull(context.Background(), "localhost/nonexistent:latest")
	// We expect an error since there's likely no daemon, or the image
	// doesn't exist. Either way, no panic.
	require.Error(t, err)
}
