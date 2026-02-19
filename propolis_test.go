// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/net/firewall"
	"github.com/stacklok/propolis/preflight"
	"github.com/stacklok/propolis/runner"
	"github.com/stacklok/propolis/state"
)

// --- Pure function tests ---

func TestBuildKrunConfig_NilOCIConfig(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	kc := buildKrunConfig(nil, cfg)

	assert.Equal(t, "/", kc.WorkingDir)
	assert.Contains(t, kc.Env[0], "PATH=")
	assert.Nil(t, kc.Cmd)
}

func TestBuildKrunConfig_WithOCIConfig(t *testing.T) {
	t.Parallel()

	ociCfg := &image.OCIConfig{
		Entrypoint: []string{"/bin/sh"},
		Cmd:        []string{"-c", "echo hello"},
		Env:        []string{"FOO=bar"},
		WorkingDir: "/app",
	}

	cfg := defaultConfig()
	kc := buildKrunConfig(ociCfg, cfg)

	assert.Equal(t, "/app", kc.WorkingDir)
	assert.Equal(t, []string{"/bin/sh", "-c", "echo hello"}, kc.Cmd)
	assert.Contains(t, kc.Env, "FOO=bar")
	// Default PATH should still be first.
	assert.Contains(t, kc.Env[0], "PATH=")
}

func TestBuildKrunConfig_WithInitOverride(t *testing.T) {
	t.Parallel()

	ociCfg := &image.OCIConfig{
		Entrypoint: []string{"/bin/sh"},
		Cmd:        []string{"-c", "echo original"},
	}

	cfg := defaultConfig()
	cfg.initOverride = []string{"/custom/init", "--flag"}
	kc := buildKrunConfig(ociCfg, cfg)

	// InitOverride should replace the OCI command.
	assert.Equal(t, []string{"/custom/init", "--flag"}, kc.Cmd)
}

func TestBuildKrunConfig_EmptyWorkingDir(t *testing.T) {
	t.Parallel()

	ociCfg := &image.OCIConfig{
		WorkingDir: "", // empty should keep default "/"
	}

	cfg := defaultConfig()
	kc := buildKrunConfig(ociCfg, cfg)

	assert.Equal(t, "/", kc.WorkingDir)
}

func TestToRunnerVirtioFS(t *testing.T) {
	t.Parallel()

	mounts := []VirtioFSMount{
		{Tag: "workspace", HostPath: "/home/user/src"},
		{Tag: "data", HostPath: "/var/data"},
	}

	result := toRunnerVirtioFS(mounts)

	require.Len(t, result, 2)
	assert.Equal(t, "workspace", result[0].Tag)
	assert.Equal(t, "/home/user/src", result[0].HostPath)
	assert.Equal(t, "data", result[1].Tag)
	assert.Equal(t, "/var/data", result[1].HostPath)
}

func TestToRunnerVirtioFS_Empty(t *testing.T) {
	t.Parallel()

	result := toRunnerVirtioFS(nil)
	assert.Empty(t, result)
}

// --- Mock types for Run() tests ---

// mockImageFetcher implements image.ImageFetcher for testing.
type mockImageFetcher struct {
	img v1.Image
	err error
}

func (m *mockImageFetcher) Pull(_ context.Context, _ string) (v1.Image, error) {
	return m.img, m.err
}

// mockSpawner implements runner.Spawner for testing.
type mockSpawner struct {
	proc runner.ProcessHandle
	err  error
}

func (m *mockSpawner) Spawn(_ context.Context, _ runner.Config) (runner.ProcessHandle, error) {
	return m.proc, m.err
}

// failingChecker is a preflight.Checker that always fails.
type failingChecker struct {
	err error
}

func (f *failingChecker) RunAll(_ context.Context) error { return f.err }
func (f *failingChecker) Register(_ preflight.Check)     {}

// --- Run() integration tests ---

func TestRun_PreflightFailure(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(&failingChecker{err: fmt.Errorf("KVM not available")}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "preflight")
	assert.Contains(t, err.Error(), "KVM not available")
}

func TestRun_ImagePullFailure(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithImageFetcher(&mockImageFetcher{err: fmt.Errorf("network timeout")}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pull image")
}

func TestRun_SpawnFailure(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Create a fake rootfs so we skip image pull.
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithSpawner(&mockSpawner{err: fmt.Errorf("runner not found")}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "spawn vm")
	// Net provider should have been stopped on spawn failure.
	assert.True(t, netProv.stopped)
}

func TestRun_WithCleanDataDir_RemovesStaleState(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	cacheDir := filepath.Join(dataDir, "cache")
	stalePath := filepath.Join(dataDir, "stale.sock")

	require.NoError(t, os.MkdirAll(cacheDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(cacheDir, "marker"), []byte("cache"), 0o644))
	require.NoError(t, os.WriteFile(stalePath, []byte("stale"), 0o644))

	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	proc := &mockProcessHandle{pid: 1234, alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithCleanDataDir(),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithSpawner(&mockSpawner{proc: proc}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)

	_, err = os.Stat(stalePath)
	assert.True(t, os.IsNotExist(err))

	_, err = os.Stat(cacheDir)
	require.NoError(t, err)

	_, err = os.Stat(rootfsDir)
	require.NoError(t, err)
}

func TestRun_Success(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Create a fake rootfs.
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	proc := &mockProcessHandle{pid: 1234, alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithName("test-vm"),
		WithCPUs(2),
		WithMemory(1024),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithSpawner(&mockSpawner{proc: proc}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)

	assert.Equal(t, "test-vm", vm.Name())
	assert.Equal(t, 1234, vm.PID())
	assert.Equal(t, rootfsDir, vm.RootFSPath())

	// Verify state was persisted for crash recovery.
	mgr := state.NewManager(dataDir)
	loaded, loadErr := mgr.Load()
	require.NoError(t, loadErr)
	assert.True(t, loaded.Active)
	assert.Equal(t, "test-vm", loaded.Name)
	assert.Equal(t, 1234, loaded.PID)
	assert.Equal(t, "test:latest", loaded.Image)
	assert.Equal(t, uint32(2), loaded.CPUs)
	assert.Equal(t, uint32(1024), loaded.MemoryMB)
}

func TestRun_WithRootFSPath_SkipsImagePull(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	// Image fetcher should NOT be called since rootfs path is set.
	fetcher := &mockImageFetcher{err: fmt.Errorf("should not be called")}
	proc := &mockProcessHandle{pid: 42, alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithImageFetcher(fetcher),
		WithNetProvider(netProv),
		WithSpawner(&mockSpawner{proc: proc}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)
	assert.Equal(t, rootfsDir, vm.RootFSPath())
}

func TestRun_PostBootHookError(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	proc := &mockProcessHandle{pid: 42, alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithSpawner(&mockSpawner{proc: proc}),
		WithPostBoot(func(_ context.Context, _ *VM) error {
			return fmt.Errorf("hook failed")
		}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post-boot hook")
	// Process and net provider should be stopped on post-boot hook failure.
	assert.True(t, proc.stopped)
	assert.True(t, netProv.stopped)
}

func TestRun_WithImageFetcher_CacheMiss(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	fetcher := &mockImageFetcher{img: fakeImg}
	proc := &mockProcessHandle{pid: 42, alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "example.com/test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithImageFetcher(fetcher),
		WithNetProvider(netProv),
		WithSpawner(&mockSpawner{proc: proc}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)
	assert.NotEmpty(t, vm.RootFSPath())
}

func TestRun_RootfsHookError(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithRootFSHook(func(_ string, _ *image.OCIConfig) error {
			return fmt.Errorf("rootfs hook failed")
		}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "rootfs hook")
}

func TestRun_NetworkingError(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	netProv := &mockNetProvider{startErr: fmt.Errorf("gvproxy not found")}

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "networking")
}

// --- buildNetConfig tests ---

func TestBuildNetConfig_WithPorts(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.ports = []PortForward{
		{Host: 8080, Guest: 80},
		{Host: 2222, Guest: 22},
	}

	netCfg := cfg.buildNetConfig()

	require.Len(t, netCfg.Forwards, 2)
	assert.Equal(t, uint16(8080), netCfg.Forwards[0].Host)
	assert.Equal(t, uint16(80), netCfg.Forwards[0].Guest)
	assert.Equal(t, uint16(2222), netCfg.Forwards[1].Host)
	assert.Equal(t, uint16(22), netCfg.Forwards[1].Guest)
}

func TestBuildNetConfig_WithEgressPolicy(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.egressPolicy = &EgressPolicy{
		AllowedHosts: []EgressHost{
			{Name: "api.github.com", Ports: []uint16{443}, Protocol: 6},
			{Name: "*.docker.io"},
		},
	}

	netCfg := cfg.buildNetConfig()

	require.NotNil(t, netCfg.EgressPolicy)
	require.Len(t, netCfg.EgressPolicy.AllowedHosts, 2)
	assert.Equal(t, "api.github.com", netCfg.EgressPolicy.AllowedHosts[0].Name)
	assert.Equal(t, []uint16{443}, netCfg.EgressPolicy.AllowedHosts[0].Ports)
	assert.Equal(t, uint8(6), netCfg.EgressPolicy.AllowedHosts[0].Protocol)
	assert.Equal(t, "*.docker.io", netCfg.EgressPolicy.AllowedHosts[1].Name)
	assert.Empty(t, netCfg.EgressPolicy.AllowedHosts[1].Ports)
	assert.Equal(t, uint8(0), netCfg.EgressPolicy.AllowedHosts[1].Protocol)
}

func TestBuildNetConfig_Empty(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()

	netCfg := cfg.buildNetConfig()

	assert.Empty(t, netCfg.Forwards)
	assert.Nil(t, netCfg.EgressPolicy)
	assert.Empty(t, netCfg.FirewallRules)
	assert.Equal(t, firewall.Allow, netCfg.FirewallDefaultAction)
}

// --- Egress validation tests ---

func TestRun_EgressPolicy_EmptyHosts(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithEgressPolicy(EgressPolicy{AllowedHosts: nil}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "AllowedHosts must not be empty")
}

func TestRun_EgressPolicy_EmptyName(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithEgressPolicy(EgressPolicy{
			AllowedHosts: []EgressHost{{Name: ""}},
		}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Name must not be empty")
}

func TestRun_EgressPolicy_OverlyBroadWildcard(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithEgressPolicy(EgressPolicy{
			AllowedHosts: []EgressHost{{Name: "*.com"}},
		}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "wildcard must have at least two domain labels")
}

func TestRun_EgressPolicy_ValidWildcard(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	proc := &mockProcessHandle{pid: 99, alive: true}

	// ValidWildcard should pass egress validation and proceed.
	// We use a mock spawner to prevent the actual VM spawn from failing
	// for unrelated reasons (no runner binary, etc.).
	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithSpawner(&mockSpawner{proc: proc}),
		WithEgressPolicy(EgressPolicy{
			AllowedHosts: []EgressHost{{Name: "*.example.com"}},
		}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)
}

// --- toRunnerPortForwards tests ---

func TestToRunnerPortForwards(t *testing.T) {
	t.Parallel()

	ports := []PortForward{
		{Host: 8080, Guest: 80},
		{Host: 2222, Guest: 22},
		{Host: 3000, Guest: 3000},
	}

	result := toRunnerPortForwards(ports)

	require.Len(t, result, 3)
	assert.Equal(t, uint16(8080), result[0].Host)
	assert.Equal(t, uint16(80), result[0].Guest)
	assert.Equal(t, uint16(2222), result[1].Host)
	assert.Equal(t, uint16(22), result[1].Guest)
	assert.Equal(t, uint16(3000), result[2].Host)
	assert.Equal(t, uint16(3000), result[2].Guest)
}

func TestToRunnerPortForwards_Nil(t *testing.T) {
	t.Parallel()

	result := toRunnerPortForwards(nil)
	assert.Empty(t, result)
}

// --- Option tests for new DI options ---

func TestWithImageFetcher(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Nil(t, cfg.imageFetcher)

	fetcher := &mockImageFetcher{}
	WithImageFetcher(fetcher).apply(cfg)
	assert.Equal(t, fetcher, cfg.imageFetcher)
}

func TestWithSpawner(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Nil(t, cfg.spawner)

	spawner := &mockSpawner{}
	WithSpawner(spawner).apply(cfg)
	assert.Equal(t, spawner, cfg.spawner)
}
