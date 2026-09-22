// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package virtiofs

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestPrepareOwnershipMatchingMetadataIsNotRewritten(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(file, []byte("data"), 0o640))
	require.NoError(t, PrepareOwnership(context.Background(), root, "file", 65532, 65532))
	// libkrun interprets the mode as octal with or without a leading zero.
	// Preserve an equivalent non-canonical representation rather than rewriting it.
	require.NoError(t, unix.Lsetxattr(file, overrideKey, []byte("65532:65532:100640"), 0))

	var before unix.Stat_t
	require.NoError(t, unix.Lstat(file, &before))
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, PrepareOwnership(context.Background(), root, "file", 65532, 65532))
	var after unix.Stat_t
	require.NoError(t, unix.Lstat(file, &after))

	assert.Equal(t, before.Ctim, after.Ctim, "semantically matching xattr should not be rewritten")
	assert.Equal(t, "65532:65532:100640", getOverride(t, file))
}

func TestPrepareOwnershipLaterSubtreeDoesNotRescanSiblings(t *testing.T) {
	root := t.TempDir()
	unrelated := filepath.Join(root, "unrelated")
	require.NoError(t, os.WriteFile(unrelated, []byte("data"), 0o600))
	require.NoError(t, unix.Lsetxattr(unrelated, overrideKey, []byte("malformed"), 0))

	created := filepath.Join(root, "created", "nested")
	require.NoError(t, os.MkdirAll(created, 0o755))
	require.NoError(t, PrepareOwnership(context.Background(), root, "created", 65532, 65532))

	assert.Contains(t, getOverride(t, created), "65532:65532:")
	assert.Equal(t, "malformed", getOverride(t, unrelated))
}
