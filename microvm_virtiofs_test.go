// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package microvm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/stacklok/go-microvm/guest/vmconfig"
	"github.com/stacklok/go-microvm/preflight"
	"github.com/stacklok/go-microvm/virtiofs"
)

func TestRunPreparesWritableVirtioFSOwnership(t *testing.T) {
	dataDir := t.TempDir()
	rootfs := filepath.Join(dataDir, "rootfs")
	share := filepath.Join(dataDir, "share")
	require.NoError(t, os.Mkdir(rootfs, 0o755))
	require.NoError(t, os.Mkdir(share, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(share, "data"), []byte("x"), 0o640))
	require.NoError(t, unix.Lsetxattr(filepath.Join(share, "data"), "user.containers.override_stat", []byte("12:13:0100600"), 0))

	backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}
	vm, err := Run(context.Background(), "unused",
		WithDataDir(dataDir), WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfs), WithBackend(backend),
		WithVirtioFS(VirtioFSMount{Tag: "share", HostPath: share, OverrideUID: 65532}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vm.Stop(context.Background()) })
	assert.Equal(t, "65532:65532:0100600", readOverrideForRunTest(t, filepath.Join(share, "data")))
}

func TestRunOwnershipFailurePreventsNetworkAndBackendStart(t *testing.T) {
	dataDir := t.TempDir()
	rootfs := filepath.Join(dataDir, "rootfs")
	share := filepath.Join(dataDir, "share")
	require.NoError(t, os.Mkdir(rootfs, 0o755))
	require.NoError(t, os.Mkdir(share, 0o755))
	require.NoError(t, unix.Lsetxattr(share, "user.containers.override_stat", []byte("malformed"), 0))

	backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}
	provider := &mockNetProvider{}
	_, err := Run(context.Background(), "unused",
		WithDataDir(dataDir), WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfs), WithBackend(backend), WithNetProvider(provider),
		WithVirtioFS(VirtioFSMount{Tag: "share", HostPath: share, OverrideUID: 65532, StrictOwnershipPreparation: true}),
	)
	require.ErrorContains(t, err, "prepare virtiofs mount \"share\" ownership")
	assert.Zero(t, provider.startCalls)
	assert.Zero(t, backend.startCalls)
}

func TestRunPreparesReadOnlyMountAndPreservesReadOnlyFlags(t *testing.T) {
	dataDir := t.TempDir()
	rootfs := filepath.Join(dataDir, "rootfs")
	share := filepath.Join(dataDir, "share")
	require.NoError(t, os.Mkdir(rootfs, 0o755))
	require.NoError(t, os.Mkdir(share, 0o700))
	data := filepath.Join(share, "data")
	require.NoError(t, os.WriteFile(data, []byte("readonly"), 0o640))
	beforeDir, err := os.Stat(share)
	require.NoError(t, err)
	beforeData, err := os.Stat(data)
	require.NoError(t, err)

	backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}
	vm, err := Run(context.Background(), "unused",
		WithDataDir(dataDir), WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfs), WithBackend(backend),
		WithVirtioFS(VirtioFSMount{Tag: "share", HostPath: share, ReadOnly: true, OverrideUID: 65532}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vm.Stop(context.Background()) })
	require.Len(t, backend.lastConfig.FilesystemMounts, 1)
	assert.True(t, backend.lastConfig.FilesystemMounts[0].ReadOnly)

	afterDir, err := os.Stat(share)
	require.NoError(t, err)
	afterData, err := os.Stat(data)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), afterDir.Mode().Perm())
	assert.Equal(t, os.FileMode(0o640), afterData.Mode().Perm())
	assert.Equal(t, "65532:65532:0100640", readOverrideForRunTest(t, data))
	assert.Equal(t, beforeDir.Sys().(*syscall.Stat_t).Uid, afterDir.Sys().(*syscall.Stat_t).Uid)
	assert.Equal(t, beforeDir.Sys().(*syscall.Stat_t).Gid, afterDir.Sys().(*syscall.Stat_t).Gid)
	assert.Equal(t, beforeData.Sys().(*syscall.Stat_t).Uid, afterData.Sys().(*syscall.Stat_t).Uid)
	assert.Equal(t, beforeData.Sys().(*syscall.Stat_t).Gid, afterData.Sys().(*syscall.Stat_t).Gid)

	configData, err := os.ReadFile(filepath.Join(rootfs, vmconfig.GuestPath))
	require.NoError(t, err)
	var guestConfig vmconfig.Config
	require.NoError(t, json.Unmarshal(configData, &guestConfig))
	require.Equal(t, []vmconfig.VirtioFSMountInfo{{Tag: "share", ReadOnly: true}}, guestConfig.VirtioFSMounts)
}

func TestRunDoesNotTraverseMountWithoutOverride(t *testing.T) {
	dataDir := t.TempDir()
	rootfs := filepath.Join(dataDir, "rootfs")
	share := filepath.Join(dataDir, "share")
	require.NoError(t, os.Mkdir(rootfs, 0o755))
	require.NoError(t, os.Mkdir(share, 0o755))
	require.NoError(t, unix.Lsetxattr(share, "user.containers.override_stat", []byte("malformed"), 0))
	backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}
	vm, err := Run(context.Background(), "unused",
		WithDataDir(dataDir), WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfs), WithBackend(backend),
		WithVirtioFS(VirtioFSMount{Tag: "share", HostPath: share, ReadOnly: true, StrictOwnershipPreparation: true}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vm.Stop(context.Background()) })
	assert.Equal(t, "malformed", readOverrideForRunTest(t, share))
	assert.Equal(t, 1, backend.startCalls)
}

func TestRunBestEffortOwnershipDoesNotSwallowCancellation(t *testing.T) {
	dataDir := t.TempDir()
	rootfs := filepath.Join(dataDir, "rootfs")
	share := filepath.Join(dataDir, "share")
	require.NoError(t, os.Mkdir(rootfs, 0o755))
	require.NoError(t, os.Mkdir(share, 0o755))
	backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}
	provider := &mockNetProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := Run(ctx, "unused",
		WithDataDir(dataDir), WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfs), WithBackend(backend), WithNetProvider(provider),
		WithVirtioFS(VirtioFSMount{Tag: "share", HostPath: share, OverrideUID: 65532}),
	)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, provider.startCalls)
	assert.Zero(t, backend.startCalls)
}

func TestRunValidatesAllOwnershipMountsBeforeStamping(t *testing.T) {
	dataDir := t.TempDir()
	rootfs := filepath.Join(dataDir, "rootfs")
	first := filepath.Join(dataDir, "first")
	require.NoError(t, os.Mkdir(rootfs, 0o755))
	require.NoError(t, os.Mkdir(first, 0o755))
	backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}

	_, err := Run(context.Background(), "unused",
		WithDataDir(dataDir), WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfs), WithBackend(backend),
		WithVirtioFS(
			VirtioFSMount{Tag: "first", HostPath: first, OverrideUID: 65532},
			VirtioFSMount{Tag: "invalid", HostPath: first, OverrideGID: 1},
		),
	)
	require.ErrorContains(t, err, "OverrideGID set without OverrideUID")
	_, xattrErr := unix.Lgetxattr(first, "user.containers.override_stat", make([]byte, 256))
	assert.Error(t, xattrErr)
	assert.Zero(t, backend.startCalls)
}

func TestRunBestEffortOwnershipContinuesMountAndSubsequentMounts(t *testing.T) {
	dataDir := t.TempDir()
	rootfs := filepath.Join(dataDir, "rootfs")
	first := filepath.Join(dataDir, "first")
	second := filepath.Join(dataDir, "second")
	require.NoError(t, os.Mkdir(rootfs, 0o755))
	require.NoError(t, os.Mkdir(first, 0o755))
	require.NoError(t, os.Mkdir(second, 0o755))
	require.NoError(t, unix.Lsetxattr(first, "user.containers.override_stat", []byte("malformed"), 0))
	firstChild := filepath.Join(first, "child")
	secondChild := filepath.Join(second, "child")
	require.NoError(t, os.WriteFile(firstChild, nil, 0o600))
	require.NoError(t, os.WriteFile(secondChild, nil, 0o640))

	backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}
	vm, err := Run(context.Background(), "unused",
		WithDataDir(dataDir), WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfs), WithBackend(backend),
		WithVirtioFS(
			VirtioFSMount{Tag: "first", HostPath: first, OverrideUID: 65532},
			VirtioFSMount{Tag: "second", HostPath: second, OverrideUID: 65532},
		),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vm.Stop(context.Background()) })
	assert.Equal(t, "malformed", readOverrideForRunTest(t, first))
	assert.Equal(t, "65532:65532:0100600", readOverrideForRunTest(t, firstChild))
	assert.Equal(t, "65532:65532:0100640", readOverrideForRunTest(t, secondChild))
	assert.Equal(t, 1, backend.startCalls)
}

func TestPrepareOwnershipAfterRunTargetsReplacementWithoutRestart(t *testing.T) {
	dataDir := t.TempDir()
	rootfs := filepath.Join(dataDir, "rootfs")
	share := filepath.Join(dataDir, "share")
	require.NoError(t, os.Mkdir(rootfs, 0o755))
	require.NoError(t, os.Mkdir(share, 0o755))
	unrelated := filepath.Join(share, "unrelated")
	require.NoError(t, os.WriteFile(unrelated, nil, 0o644))
	require.NoError(t, unix.Lsetxattr(unrelated, "user.containers.override_stat", []byte("65532:65532:0100600"), 0))
	target := filepath.Join(share, "target")
	require.NoError(t, os.WriteFile(target, []byte("old"), 0o600))

	backend := &mockBackend{startHandle: &mockVMHandle{id: "42", alive: true}}
	vm, err := Run(context.Background(), "unused",
		WithDataDir(dataDir), WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfs), WithBackend(backend),
		WithVirtioFS(VirtioFSMount{Tag: "share", HostPath: share}),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = vm.Stop(context.Background()) })

	staged := filepath.Join(share, "staged")
	require.NoError(t, os.WriteFile(staged, []byte("new"), 0o640))
	require.NoError(t, os.Rename(staged, target))
	require.NoError(t, virtiofs.PrepareOwnership(context.Background(), share, "target", 65532, 65532))

	assert.Equal(t, "65532:65532:0100640", readOverrideForRunTest(t, target))
	assert.Equal(t, "65532:65532:0100600", readOverrideForRunTest(t, unrelated))
	assert.Equal(t, 1, backend.startCalls)
}

func readOverrideForRunTest(t *testing.T, path string) string {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, "user.containers.override_stat", buf)
	require.NoError(t, err)
	return string(buf[:n])
}
