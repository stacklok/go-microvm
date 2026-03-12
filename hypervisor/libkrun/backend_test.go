// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package libkrun

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/extract"
	"github.com/stacklok/propolis/hypervisor"
	"github.com/stacklok/propolis/runner"
)

func TestBackend_Name(t *testing.T) {
	t.Parallel()

	b := NewBackend()
	assert.Equal(t, "libkrun", b.Name())
}

func TestBackend_PrepareRootFS_WritesKrunConfig(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	b := NewBackend()

	initCfg := hypervisor.InitConfig{
		Cmd:        []string{"/bin/sh", "-c", "echo hello"},
		Env:        []string{"PATH=/usr/bin", "FOO=bar"},
		WorkingDir: "/app",
	}

	path, err := b.PrepareRootFS(context.Background(), rootfs, initCfg)
	require.NoError(t, err)
	assert.Equal(t, rootfs, path)

	// Verify .krun_config.json was written.
	configPath := filepath.Join(rootfs, ".krun_config.json")
	data, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "/bin/sh")
	assert.Contains(t, string(data), "FOO=bar")
	assert.Contains(t, string(data), "/app")
}

func TestBackend_PrepareRootFS_InvalidPath(t *testing.T) {
	t.Parallel()

	b := NewBackend()
	initCfg := hypervisor.InitConfig{Cmd: []string{"/bin/true"}}

	_, err := b.PrepareRootFS(context.Background(), "/nonexistent/path", initCfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "write krun config")
}

func TestBackend_Options(t *testing.T) {
	t.Parallel()

	b := NewBackend(
		WithRunnerPath("/custom/runner"),
		WithLibDir("/custom/lib"),
	)

	assert.Equal(t, "/custom/runner", b.runnerPath)
	assert.Equal(t, "/custom/lib", b.libDir)
}

// mockSpawner implements runner.Spawner for testing.
type mockSpawner struct {
	proc runner.ProcessHandle
	err  error
}

func (m *mockSpawner) Spawn(_ context.Context, _ runner.Config) (runner.ProcessHandle, error) {
	return m.proc, m.err
}

// mockProcessHandle implements runner.ProcessHandle for testing.
type mockProcessHandle struct {
	pid     int
	alive   bool
	stopped bool
}

func (m *mockProcessHandle) Stop(_ context.Context) error {
	m.stopped = true
	m.alive = false
	return nil
}

func (m *mockProcessHandle) IsAlive() bool { return m.alive }
func (m *mockProcessHandle) PID() int      { return m.pid }

func TestBackend_Start_Success(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 42, alive: true}
	b := NewBackend(WithSpawner(&mockSpawner{proc: proc}))

	rootfs := t.TempDir()
	cfg := hypervisor.VMConfig{
		Name:       "test-vm",
		RootFSPath: rootfs,
		NumVCPUs:   2,
		RAMMiB:     512,
		DataDir:    t.TempDir(),
		PortForwards: []hypervisor.PortForward{
			{Host: 8080, Guest: 80},
		},
		FilesystemMounts: []hypervisor.FilesystemMount{
			{Tag: "workspace", HostPath: "/tmp/src"},
		},
		NetEndpoint: hypervisor.NetEndpoint{
			Type: hypervisor.NetEndpointUnixSocket,
			Path: "/tmp/net.sock",
		},
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	assert.True(t, handle.IsAlive())
	assert.Equal(t, "42", handle.ID())
}

func TestBackend_Start_SpawnError(t *testing.T) {
	t.Parallel()

	b := NewBackend(WithSpawner(&mockSpawner{
		err: assert.AnError,
	}))

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.Error(t, err)
	assert.Nil(t, handle)
	assert.Contains(t, err.Error(), "spawn runner")
}

func TestProcessHandle_Lifecycle(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 99, alive: true}
	h := &processHandle{proc: proc}

	assert.Equal(t, "99", h.ID())
	assert.True(t, h.IsAlive())

	err := h.Stop(context.Background())
	require.NoError(t, err)
	assert.False(t, h.IsAlive())
}

func TestBackend_Start_NoNetEndpoint(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 10, alive: true}
	b := NewBackend(WithSpawner(&mockSpawner{proc: proc}))

	cfg := hypervisor.VMConfig{
		RootFSPath:  t.TempDir(),
		DataDir:     t.TempDir(),
		NetEndpoint: hypervisor.NetEndpoint{Type: hypervisor.NetEndpointNone},
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "10", handle.ID())
}

// captureSpawner records the runner.Config passed to Spawn.
type captureSpawner struct {
	captured runner.Config
	proc     runner.ProcessHandle
	err      error
}

func (s *captureSpawner) Spawn(_ context.Context, cfg runner.Config) (runner.ProcessHandle, error) {
	s.captured = cfg
	return s.proc, s.err
}

// mockSource implements extract.Source for testing.
type mockSource struct {
	dir              string
	err              error
	capturedCacheDir string
}

func (m *mockSource) Ensure(_ context.Context, cacheDir string) (string, error) {
	m.capturedCacheDir = cacheDir
	return m.dir, m.err
}

// makeRuntimeDir creates a temp directory with a dummy propolis-runner binary.
func makeRuntimeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, extract.RunnerBinaryName), []byte("dummy"), 0o755))
	return dir
}

func TestBackend_Validate_RuntimeAndRunnerPathConflict(t *testing.T) {
	t.Parallel()

	b := NewBackend(
		WithRuntime(&mockSource{dir: "/tmp"}),
		WithRunnerPath("/custom/runner"),
	)

	_, err := b.Start(context.Background(), hypervisor.VMConfig{DataDir: t.TempDir()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestBackend_Validate_RuntimeAndLibDirConflict(t *testing.T) {
	t.Parallel()

	b := NewBackend(
		WithRuntime(&mockSource{dir: "/tmp"}),
		WithLibDir("/custom/lib"),
	)

	_, err := b.Start(context.Background(), hypervisor.VMConfig{DataDir: t.TempDir()})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

func TestBackend_Start_WithRuntime(t *testing.T) {
	t.Parallel()

	runtimeDir := makeRuntimeDir(t)
	proc := &mockProcessHandle{pid: 1, alive: true}
	spawner := &captureSpawner{proc: proc}
	rtSource := &mockSource{dir: runtimeDir}

	b := NewBackend(
		WithRuntime(rtSource),
		WithCacheDir("/my/cache"),
		WithSpawner(spawner),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	assert.Equal(t, filepath.Join(runtimeDir, extract.RunnerBinaryName), spawner.captured.RunnerPath)
	assert.Equal(t, runtimeDir, spawner.captured.LibDir)
	assert.Equal(t, "/my/cache", rtSource.capturedCacheDir)
}

func TestBackend_Start_WithFirmware(t *testing.T) {
	t.Parallel()

	fwDir := t.TempDir()
	proc := &mockProcessHandle{pid: 2, alive: true}
	spawner := &captureSpawner{proc: proc}

	b := NewBackend(
		WithFirmware(&mockSource{dir: fwDir}),
		WithSpawner(spawner),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	assert.Equal(t, fwDir, spawner.captured.LibDir)
}

func TestBackend_Start_WithRuntimeAndFirmware(t *testing.T) {
	t.Parallel()

	runtimeDir := makeRuntimeDir(t)
	fwDir := t.TempDir()
	proc := &mockProcessHandle{pid: 3, alive: true}
	spawner := &captureSpawner{proc: proc}

	b := NewBackend(
		WithRuntime(&mockSource{dir: runtimeDir}),
		WithFirmware(&mockSource{dir: fwDir}),
		WithSpawner(spawner),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	expectedLibDir := runtimeDir + string(os.PathListSeparator) + fwDir
	assert.Equal(t, expectedLibDir, spawner.captured.LibDir)
	assert.Equal(t, filepath.Join(runtimeDir, extract.RunnerBinaryName), spawner.captured.RunnerPath)
}

func TestBackend_Start_WithFirmwareAndLibDir(t *testing.T) {
	t.Parallel()

	existingLib := "/existing/lib"
	fwDir := t.TempDir()
	proc := &mockProcessHandle{pid: 4, alive: true}
	spawner := &captureSpawner{proc: proc}

	b := NewBackend(
		WithLibDir(existingLib),
		WithFirmware(&mockSource{dir: fwDir}),
		WithSpawner(spawner),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	expectedLibDir := existingLib + string(os.PathListSeparator) + fwDir
	assert.Equal(t, expectedLibDir, spawner.captured.LibDir)
}

func TestBackend_Start_RuntimeEnsureError(t *testing.T) {
	t.Parallel()

	b := NewBackend(
		WithRuntime(&mockSource{err: errors.New("download failed")}),
		WithSpawner(&mockSpawner{proc: &mockProcessHandle{}}),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	_, err := b.Start(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve runtime")
	assert.Contains(t, err.Error(), "download failed")
}

func TestBackend_Start_FirmwareEnsureError(t *testing.T) {
	t.Parallel()

	b := NewBackend(
		WithFirmware(&mockSource{err: errors.New("firmware fetch failed")}),
		WithSpawner(&mockSpawner{proc: &mockProcessHandle{}}),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	_, err := b.Start(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve firmware")
	assert.Contains(t, err.Error(), "firmware fetch failed")
}

func TestBackend_Start_RuntimeMissingRunner(t *testing.T) {
	t.Parallel()

	// Dir exists but has no propolis-runner binary.
	emptyDir := t.TempDir()

	b := NewBackend(
		WithRuntime(&mockSource{dir: emptyDir}),
		WithSpawner(&mockSpawner{proc: &mockProcessHandle{}}),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	_, err := b.Start(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "propolis-runner not found")
}

func TestBackend_Options_Sources(t *testing.T) {
	t.Parallel()

	rt := &mockSource{dir: "/rt"}
	fw := &mockSource{dir: "/fw"}

	b := NewBackend(
		WithRuntime(rt),
		WithFirmware(fw),
		WithCacheDir("/cache"),
	)

	assert.Equal(t, rt, b.runtime)
	assert.Equal(t, fw, b.firmware)
	assert.Equal(t, "/cache", b.cacheDir)
}

func TestBackend_Start_DefaultUnchanged(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 50, alive: true}
	spawner := &captureSpawner{proc: proc}

	b := NewBackend(
		WithRunnerPath("/my/runner"),
		WithLibDir("/my/lib"),
		WithSpawner(spawner),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// Verify existing options still flow through unchanged.
	assert.Equal(t, "/my/runner", spawner.captured.RunnerPath)
	assert.Equal(t, "/my/lib", spawner.captured.LibDir)
}

func TestBackend_Options_UserNamespaceUID(t *testing.T) {
	t.Parallel()

	b := NewBackend(WithUserNamespaceUID(1000, 1000))

	require.NotNil(t, b.userNamespace)
	assert.Equal(t, uint32(1000), b.userNamespace.UID)
	assert.Equal(t, uint32(1000), b.userNamespace.GID)
}

func TestBackend_Start_WithUserNamespaceUID(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 77, alive: true}
	spawner := &captureSpawner{proc: proc}

	b := NewBackend(
		WithUserNamespaceUID(1000, 1000),
		WithSpawner(spawner),
	)

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// Verify the user namespace config was threaded through.
	require.NotNil(t, spawner.captured.UserNamespace)
	assert.Equal(t, uint32(1000), spawner.captured.UserNamespace.UID)
	assert.Equal(t, uint32(1000), spawner.captured.UserNamespace.GID)
}

func TestBackend_Start_WithoutUserNamespace(t *testing.T) {
	t.Parallel()

	proc := &mockProcessHandle{pid: 78, alive: true}
	spawner := &captureSpawner{proc: proc}

	b := NewBackend(WithSpawner(spawner))

	cfg := hypervisor.VMConfig{
		RootFSPath: t.TempDir(),
		DataDir:    t.TempDir(),
	}

	handle, err := b.Start(context.Background(), cfg)
	require.NoError(t, err)
	require.NotNil(t, handle)

	// UserNamespace should be nil when not configured.
	assert.Nil(t, spawner.captured.UserNamespace)
}

// Verify mockSource implements extract.Source.
var _ extract.Source = (*mockSource)(nil)
