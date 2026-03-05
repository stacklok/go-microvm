// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/hypervisor"
	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/internal/testutil"
	"github.com/stacklok/propolis/net/firewall"
	"github.com/stacklok/propolis/preflight"
	"github.com/stacklok/propolis/state"
)

// --- Pure function tests ---

func TestBuildInitConfig_NilOCIConfig(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	ic := buildInitConfig(nil, cfg)

	assert.Equal(t, "/", ic.WorkingDir)
	assert.Contains(t, ic.Env[0], "PATH=")
	assert.Nil(t, ic.Cmd)
}

func TestBuildInitConfig_WithOCIConfig(t *testing.T) {
	t.Parallel()

	ociCfg := &image.OCIConfig{
		Entrypoint: []string{"/bin/sh"},
		Cmd:        []string{"-c", "echo hello"},
		Env:        []string{"FOO=bar"},
		WorkingDir: "/app",
	}

	cfg := defaultConfig()
	ic := buildInitConfig(ociCfg, cfg)

	assert.Equal(t, "/app", ic.WorkingDir)
	assert.Equal(t, []string{"/bin/sh", "-c", "echo hello"}, ic.Cmd)
	assert.Contains(t, ic.Env, "FOO=bar")
	// Default PATH should still be first.
	assert.Contains(t, ic.Env[0], "PATH=")
}

func TestBuildInitConfig_WithInitOverride(t *testing.T) {
	t.Parallel()

	ociCfg := &image.OCIConfig{
		Entrypoint: []string{"/bin/sh"},
		Cmd:        []string{"-c", "echo original"},
	}

	cfg := defaultConfig()
	cfg.initOverride = []string{"/custom/init", "--flag"}
	ic := buildInitConfig(ociCfg, cfg)

	// InitOverride should replace the OCI command.
	assert.Equal(t, []string{"/custom/init", "--flag"}, ic.Cmd)
}

func TestBuildInitConfig_EmptyWorkingDir(t *testing.T) {
	t.Parallel()

	ociCfg := &image.OCIConfig{
		WorkingDir: "", // empty should keep default "/"
	}

	cfg := defaultConfig()
	ic := buildInitConfig(ociCfg, cfg)

	assert.Equal(t, "/", ic.WorkingDir)
}

func TestToHypervisorMounts(t *testing.T) {
	t.Parallel()

	mounts := []VirtioFSMount{
		{Tag: "workspace", HostPath: "/home/user/src"},
		{Tag: "data", HostPath: "/var/data"},
	}

	result := toHypervisorMounts(mounts)

	require.Len(t, result, 2)
	assert.Equal(t, "workspace", result[0].Tag)
	assert.Equal(t, "/home/user/src", result[0].HostPath)
	assert.Equal(t, "data", result[1].Tag)
	assert.Equal(t, "/var/data", result[1].HostPath)
}

func TestToHypervisorMounts_Empty(t *testing.T) {
	t.Parallel()

	result := toHypervisorMounts(nil)
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

// mockBackend implements hypervisor.Backend for testing.
type mockBackend struct {
	prepareErr  error
	preparePath string // if set, returned instead of rootfsPath
	startHandle hypervisor.VMHandle
	startErr    error
}

func (m *mockBackend) Name() string { return "mock" }

func (m *mockBackend) PrepareRootFS(_ context.Context, rootfsPath string, _ hypervisor.InitConfig) (string, error) {
	if m.prepareErr != nil {
		return "", m.prepareErr
	}
	if m.preparePath != "" {
		return m.preparePath, nil
	}
	return rootfsPath, nil
}

func (m *mockBackend) Start(_ context.Context, _ hypervisor.VMConfig) (hypervisor.VMHandle, error) {
	return m.startHandle, m.startErr
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
		WithBackend(&mockBackend{startErr: fmt.Errorf("runner not found")}),
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

	handle := &mockVMHandle{id: "1234", alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithCleanDataDir(),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithBackend(&mockBackend{startHandle: handle}),
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

func TestRun_WithCleanDataDir_ReadOnlyTree(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	// Simulate a Go module cache tree: read-only dirs and files.
	modDir := filepath.Join(dataDir, "rootfs-work", "go", "pkg", "mod", "example.com@v1.0.0")
	require.NoError(t, os.MkdirAll(modDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(modDir, "README.md"), []byte("ro"), 0o444))
	// Lock down directories to read+execute only, like Go module cache.
	require.NoError(t, os.Chmod(modDir, 0o555))
	require.NoError(t, os.Chmod(filepath.Dir(modDir), 0o555))

	handle := &mockVMHandle{id: "ro-test", alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithCleanDataDir(),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithBackend(&mockBackend{startHandle: handle}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)

	// The read-only tree should have been removed.
	_, err = os.Stat(filepath.Join(dataDir, "rootfs-work"))
	assert.True(t, os.IsNotExist(err))

	// Rootfs (kept) should still exist.
	_, err = os.Stat(rootfsDir)
	require.NoError(t, err)
}

func TestForceRemoveAll(t *testing.T) {
	t.Parallel()

	t.Run("removes read-only tree", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		nested := filepath.Join(dir, "a", "b", "c")
		require.NoError(t, os.MkdirAll(nested, 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(nested, "file.txt"), []byte("x"), 0o444))
		require.NoError(t, os.Chmod(nested, 0o555))
		require.NoError(t, os.Chmod(filepath.Dir(nested), 0o555))

		require.NoError(t, forceRemoveAll(dir))
		_, err := os.Stat(dir)
		assert.True(t, os.IsNotExist(err))
	})

	t.Run("no error on nonexistent path", func(t *testing.T) {
		t.Parallel()
		require.NoError(t, forceRemoveAll("/tmp/does-not-exist-propolis-test"))
	})
}

func TestRun_Success(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Create a fake rootfs.
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	handle := &mockVMHandle{id: "1234", alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithName("test-vm"),
		WithCPUs(2),
		WithMemory(1024),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithBackend(&mockBackend{startHandle: handle}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)

	assert.Equal(t, "test-vm", vm.Name())
	assert.Equal(t, "1234", vm.ID())
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
	handle := &mockVMHandle{id: "42", alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithImageFetcher(fetcher),
		WithNetProvider(netProv),
		WithBackend(&mockBackend{startHandle: handle}),
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

	handle := &mockVMHandle{id: "42", alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithBackend(&mockBackend{startHandle: handle}),
		WithPostBoot(func(_ context.Context, _ *VM) error {
			return fmt.Errorf("hook failed")
		}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "post-boot hook")
	// Process and net provider should be stopped on post-boot hook failure.
	assert.True(t, handle.stopped)
	assert.True(t, netProv.stopped)
}

func TestRun_WithImageFetcher_CacheMiss(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	fakeImg, err := random.Image(256, 1)
	require.NoError(t, err)

	fetcher := &mockImageFetcher{img: fakeImg}
	handle := &mockVMHandle{id: "42", alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "example.com/test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithImageFetcher(fetcher),
		WithNetProvider(netProv),
		WithBackend(&mockBackend{startHandle: handle}),
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

// --- PrepareRootFS path validation tests ---

func TestRun_PrepareRootFS_PathEscape(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	// Backend returns a path outside the rootfs — should be rejected.
	_, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithBackend(&mockBackend{preparePath: "/etc"}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "backend returned rootfs path outside original")
}

func TestRun_PrepareRootFS_SubdirAllowed(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	rootfsDir := filepath.Join(dataDir, "rootfs")
	subDir := filepath.Join(rootfsDir, "inner")
	require.NoError(t, os.MkdirAll(subDir, 0o755))

	handle := &mockVMHandle{id: "42", alive: true}

	// Backend returns a subdirectory — should be allowed.
	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(&mockNetProvider{sockPath: "/tmp/fake.sock"}),
		WithBackend(&mockBackend{preparePath: subDir, startHandle: handle}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)
}

// --- pidFromID tests ---

func TestPidFromID_Valid(t *testing.T) {
	t.Parallel()

	pid, err := pidFromID("1234")
	require.NoError(t, err)
	assert.Equal(t, 1234, pid)
}

func TestPidFromID_NonNumeric(t *testing.T) {
	t.Parallel()

	_, err := pidFromID("abc-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse VM ID")
}

func TestPidFromID_Zero(t *testing.T) {
	t.Parallel()

	_, err := pidFromID("0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PID")
}

func TestPidFromID_Negative(t *testing.T) {
	t.Parallel()

	_, err := pidFromID("-1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid PID")
}

func TestPidFromID_Empty(t *testing.T) {
	t.Parallel()

	_, err := pidFromID("")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse VM ID")
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

	// Use a short temp dir to keep the Unix socket path under macOS's
	// 104-byte bind() limit (t.TempDir() + this test name is too long).
	dataDir := testutil.ShortTempDir(t)

	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	handle := &mockVMHandle{id: "99", alive: true}

	// ValidWildcard should pass egress validation and proceed.
	// We use a mock backend to prevent the actual VM spawn from failing
	// for unrelated reasons (no runner binary, etc.).
	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithBackend(&mockBackend{startHandle: handle}),
		WithEgressPolicy(EgressPolicy{
			AllowedHosts: []EgressHost{{Name: "*.example.com"}},
		}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)
}

// --- toHypervisorPorts tests ---

func TestToHypervisorPorts(t *testing.T) {
	t.Parallel()

	ports := []PortForward{
		{Host: 8080, Guest: 80},
		{Host: 2222, Guest: 22},
		{Host: 3000, Guest: 3000},
	}

	result := toHypervisorPorts(ports)

	require.Len(t, result, 3)
	assert.Equal(t, uint16(8080), result[0].Host)
	assert.Equal(t, uint16(80), result[0].Guest)
	assert.Equal(t, uint16(2222), result[1].Host)
	assert.Equal(t, uint16(22), result[1].Guest)
	assert.Equal(t, uint16(3000), result[2].Host)
	assert.Equal(t, uint16(3000), result[2].Guest)
}

func TestToHypervisorPorts_Nil(t *testing.T) {
	t.Parallel()

	result := toHypervisorPorts(nil)
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

func TestWithBackend(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Nil(t, cfg.backend)

	backend := &mockBackend{}
	WithBackend(backend).apply(cfg)
	assert.Equal(t, backend, cfg.backend)
}

// --- terminateStaleRunner tests ---

func TestTerminateStaleRunner_NoStateFile(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()
	cfg := defaultConfig()
	cfg.dataDir = dataDir

	// Should not panic or error when no state file exists.
	terminateStaleRunner(cfg)
}

func TestTerminateStaleRunner_DeadProcess(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Write state with a PID that doesn't exist.
	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = true
	ls.State.PID = 2147483647 // max PID, almost certainly dead
	require.NoError(t, ls.Save())
	ls.Release()

	cfg := defaultConfig()
	cfg.dataDir = dataDir

	var killCalled bool
	cfg.killProcess = func(_ int, _ syscall.Signal) error {
		killCalled = true
		return nil
	}
	cfg.processAlive = func(_ int) bool { return false }

	terminateStaleRunner(cfg)
	assert.False(t, killCalled, "should not attempt to kill a dead process")
}

func TestTerminateStaleRunner_AliveProcess_GracefulExit(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = true
	ls.State.PID = 99999
	require.NoError(t, ls.Save())
	ls.Release()

	cfg := defaultConfig()
	cfg.dataDir = dataDir

	var mu sync.Mutex
	var signals []syscall.Signal
	aliveCount := 0

	cfg.killProcess = func(pid int, sig syscall.Signal) error {
		assert.Equal(t, -99999, pid, "should signal the process group (negative PID)")
		mu.Lock()
		signals = append(signals, sig)
		mu.Unlock()
		return nil
	}
	cfg.processAlive = func(_ int) bool {
		mu.Lock()
		defer mu.Unlock()
		aliveCount++
		// Process is alive on first check (before SIGTERM), dead on second
		// (after SIGTERM + first poll).
		return aliveCount <= 1
	}

	terminateStaleRunner(cfg)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, signals, 1, "should only send SIGTERM")
	assert.Equal(t, syscall.SIGTERM, signals[0])
}

func TestTerminateStaleRunner_AliveProcess_RequiresKill(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = true
	ls.State.PID = 99999
	require.NoError(t, ls.Save())
	ls.Release()

	cfg := defaultConfig()
	cfg.dataDir = dataDir

	var mu sync.Mutex
	var signals []syscall.Signal

	cfg.killProcess = func(pid int, sig syscall.Signal) error {
		assert.Equal(t, -99999, pid, "should signal the process group (negative PID)")
		mu.Lock()
		signals = append(signals, sig)
		mu.Unlock()
		return nil
	}
	// Process never exits on its own.
	cfg.processAlive = func(_ int) bool { return true }

	terminateStaleRunner(cfg)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, signals, 2, "should send SIGTERM then SIGKILL")
	assert.Equal(t, syscall.SIGTERM, signals[0])
	assert.Equal(t, syscall.SIGKILL, signals[1])
}

func TestTerminateStaleRunner_SendsToProcessGroup(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = true
	ls.State.PID = 55555
	require.NoError(t, ls.Save())
	ls.Release()

	cfg := defaultConfig()
	cfg.dataDir = dataDir

	var mu sync.Mutex
	var receivedPIDs []int
	aliveCount := 0

	cfg.killProcess = func(pid int, _ syscall.Signal) error {
		mu.Lock()
		receivedPIDs = append(receivedPIDs, pid)
		mu.Unlock()
		return nil
	}
	cfg.processAlive = func(_ int) bool {
		mu.Lock()
		defer mu.Unlock()
		aliveCount++
		return aliveCount <= 1
	}

	terminateStaleRunner(cfg)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, receivedPIDs, 1)
	assert.Equal(t, -55555, receivedPIDs[0], "killProcess should receive negative PID for process group")
}

func TestTerminateStaleRunner_PID1_Skipped(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Write state with PID=1 (init). This must never produce kill(-1, sig).
	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = true
	ls.State.PID = 1
	require.NoError(t, ls.Save())
	ls.Release()

	cfg := defaultConfig()
	cfg.dataDir = dataDir

	var killCalled bool
	cfg.killProcess = func(_ int, _ syscall.Signal) error {
		killCalled = true
		return nil
	}
	cfg.processAlive = func(_ int) bool { return true }

	terminateStaleRunner(cfg)
	assert.False(t, killCalled, "should not attempt to kill PID 1")
}

func TestTerminateStaleRunner_ZeroPID(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Write state with PID=0 (clean shutdown).
	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = false
	ls.State.PID = 0
	require.NoError(t, ls.Save())
	ls.Release()

	cfg := defaultConfig()
	cfg.dataDir = dataDir

	var killCalled bool
	cfg.killProcess = func(_ int, _ syscall.Signal) error {
		killCalled = true
		return nil
	}

	terminateStaleRunner(cfg)
	assert.False(t, killCalled, "should not attempt to kill PID 0")
}

func TestRun_WithCleanDataDir_TerminatesStaleRunner(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Pre-populate state as if a previous runner crashed.
	mgr := state.NewManager(dataDir)
	ls, err := mgr.LoadAndLock(context.Background())
	require.NoError(t, err)
	ls.State.Active = true
	ls.State.PID = 2147483647 // dead PID
	require.NoError(t, ls.Save())
	ls.Release()

	rootfsDir := filepath.Join(dataDir, "rootfs")
	require.NoError(t, os.MkdirAll(rootfsDir, 0o755))

	handle := &mockVMHandle{id: "1234", alive: true}
	netProv := &mockNetProvider{sockPath: "/tmp/fake.sock"}

	vm, err := Run(context.Background(), "test:latest",
		WithDataDir(dataDir),
		WithCleanDataDir(),
		WithPreflightChecker(preflight.NewEmpty()),
		WithRootFSPath(rootfsDir),
		WithNetProvider(netProv),
		WithBackend(&mockBackend{startHandle: handle}),
	)
	require.NoError(t, err)
	require.NotNil(t, vm)

	// The new state should reflect the new VM, not the stale one.
	loaded, loadErr := mgr.Load()
	require.NoError(t, loadErr)
	assert.True(t, loaded.Active)
	assert.Equal(t, 1234, loaded.PID)
}
