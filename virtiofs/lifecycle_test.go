// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package virtiofs_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/stacklok/go-microvm/virtiofs"
)

const overrideStatKey = "user.containers.override_stat"

func TestPrepareOwnershipStrictPublicAPIReportsEntry(t *testing.T) {
	root := t.TempDir()
	broken := filepath.Join(root, "broken")
	require.NoError(t, os.WriteFile(broken, nil, 0o600))
	require.NoError(t, unix.Lsetxattr(broken, overrideStatKey, []byte("malformed"), 0))

	err := virtiofs.PrepareOwnership(context.Background(), root, ".", 65532, 65532)
	require.Error(t, err)
	assert.ErrorContains(t, err, "strict ownership preparation")
	assert.ErrorContains(t, err, "broken")
	assert.ErrorContains(t, err, "malformed")
}

func TestSnapshotPreparedBeforeHostReadOnlySeal(t *testing.T) {
	root := t.TempDir()
	snapshot := filepath.Join(root, "snapshot")
	require.NoError(t, os.WriteFile(snapshot, []byte("data"), 0o600))

	require.NoError(t, virtiofs.PrepareOwnership(context.Background(), root, "snapshot", 65532, 65532))
	require.NoError(t, os.Chmod(snapshot, 0o400)) // Explicit caller-owned sealing step.
	// Matching metadata requires no rewrite, so preparation still succeeds after sealing.
	require.NoError(t, virtiofs.PrepareOwnership(context.Background(), root, "snapshot", 65532, 65532))

	info, err := os.Stat(snapshot)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), info.Mode().Perm())
	assert.Equal(t, "65532:65532:0100600", readPublicOverride(t, snapshot))
}

func TestNewWorktreePreparedBeforeGuestRegistration(t *testing.T) {
	root := t.TempDir()
	worktree := filepath.Join(root, "worktrees", "job-42")
	require.NoError(t, os.MkdirAll(worktree, 0o700))
	file := filepath.Join(worktree, "checkout")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	registerGuestWorktree := func(path string) {
		assert.Equal(t, "65532:65532:0100600", readPublicOverride(t, filepath.Join(path, "checkout")))
	}
	require.NoError(t, virtiofs.PrepareOwnership(context.Background(), root, "worktrees/job-42", 65532, 65532))
	registerGuestWorktree(worktree)
}

func TestPostMergeReplacementPreparedUnderCallerSynchronization(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "result")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))
	require.NoError(t, virtiofs.PrepareOwnership(context.Background(), root, ".", 65532, 65532))

	var guestAccess sync.Mutex
	guestAccess.Lock()
	staged := filepath.Join(root, "merged")
	require.NoError(t, os.WriteFile(staged, []byte("new"), 0o640))
	require.NoError(t, os.Rename(staged, target))
	require.NoError(t, virtiofs.PrepareOwnership(context.Background(), root, "result", 65532, 65532))
	guestAccess.Unlock()

	guestAccess.Lock()
	defer guestAccess.Unlock()
	assert.Equal(t, "65532:65532:0100640", readPublicOverride(t, target))
}

func readPublicOverride(t *testing.T, path string) string {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, overrideStatKey, buf)
	require.NoError(t, err)
	return string(buf[:n])
}
