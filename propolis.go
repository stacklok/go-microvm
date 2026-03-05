// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package propolis provides a simple framework for running OCI container images
// as microVMs using libkrun.
//
// The happy path is a single function call:
//
//	vm, err := propolis.Run(ctx, "alpine:latest",
//	    propolis.WithPorts(propolis.PortForward{Host: 8080, Guest: 80}),
//	)
//	defer vm.Stop(ctx)
//
// For advanced use cases, every layer is pluggable: custom init scripts,
// rootfs hooks, network providers, preflight checks, and post-boot hooks.
package propolis

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stacklok/propolis/hypervisor"
	"github.com/stacklok/propolis/hypervisor/libkrun"
	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/net/firewall"
	"github.com/stacklok/propolis/net/hosted"
	rootfspkg "github.com/stacklok/propolis/rootfs"
	"github.com/stacklok/propolis/state"
)

// Run pulls an OCI image and boots it as a microVM. It is the primary entry
// point for the happy path. For more control, use [Create] followed by
// explicit lifecycle management.
func Run(ctx context.Context, imageRef string, opts ...Option) (*VM, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt.apply(cfg)
	}
	if cfg.cleanDataDir {
		if err := cleanDataDir(cfg); err != nil {
			return nil, err
		}
	}

	if err := os.MkdirAll(cfg.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	// Egress policy validation.
	if cfg.egressPolicy != nil {
		if len(cfg.egressPolicy.AllowedHosts) == 0 {
			return nil, fmt.Errorf("egress policy: AllowedHosts must not be empty")
		}
		for i, h := range cfg.egressPolicy.AllowedHosts {
			if h.Name == "" {
				return nil, fmt.Errorf("egress policy: AllowedHosts[%d].Name must not be empty", i)
			}
			// Reject wildcards without at least two domain labels after "*."
			// to prevent overly broad patterns like "*." or "*.com".
			if strings.HasPrefix(h.Name, "*.") {
				domain := strings.TrimSuffix(h.Name[2:], ".")
				if !strings.Contains(domain, ".") {
					return nil, fmt.Errorf(
						"egress policy: AllowedHosts[%d].Name %q wildcard must have at least two domain labels (e.g. *.example.com)",
						i, h.Name,
					)
				}
			}
		}
		if cfg.firewallDefaultAction == firewall.Allow {
			slog.Warn("egress policy overrides firewall default action to Deny")
		}
		cfg.firewallDefaultAction = firewall.Deny
		if cfg.netProvider == nil {
			cfg.netProvider = hosted.NewProvider()
		}
	}

	// 1. Preflight checks.
	slog.Debug("running preflight checks")
	if err := cfg.preflight.RunAll(ctx); err != nil {
		return nil, fmt.Errorf("preflight: %w", err)
	}

	// 2. Obtain rootfs: use pre-built path or pull OCI image.
	var rootfs *image.RootFS
	if cfg.rootfsPath != "" {
		slog.Debug("using pre-built rootfs", "path", cfg.rootfsPath)
		rootfs = &image.RootFS{Path: cfg.rootfsPath, Config: nil}
	} else {
		slog.Debug("pulling image", "ref", imageRef)
		var err error
		rootfs, err = image.PullWithFetcher(ctx, imageRef, cfg.imageCache, cfg.imageFetcher)
		if err != nil {
			return nil, fmt.Errorf("pull image: %w", err)
		}
	}

	// 2b. COW-clone cached rootfs so hooks and PrepareRootFS never
	// modify the shared cache in-place. The default libkrun backend
	// writes .krun_config.json into the rootfs, so we must always
	// clone — not just when hooks are present.
	if rootfs.FromCache {
		workDir := filepath.Join(cfg.dataDir, "rootfs-work")
		if err := rootfspkg.CloneDir(rootfs.Path, workDir); err != nil {
			return nil, fmt.Errorf("clone rootfs: %w", err)
		}
		rootfs = &image.RootFS{Path: workDir, Config: rootfs.Config}
	}

	// 3. Run rootfs hooks (no-op on happy path).
	for _, hook := range cfg.rootfsHooks {
		if err := hook(rootfs.Path, rootfs.Config); err != nil {
			return nil, fmt.Errorf("rootfs hook: %w", err)
		}
	}

	// 4. Prepare rootfs via backend.
	backend := cfg.backend
	if backend == nil {
		backend = libkrun.NewBackend()
	}
	initCfg := buildInitConfig(rootfs.Config, cfg)
	preparedPath, err := backend.PrepareRootFS(ctx, rootfs.Path, initCfg)
	if err != nil {
		return nil, fmt.Errorf("prepare rootfs: %w", err)
	}
	if !isWithin(rootfs.Path, preparedPath) && preparedPath != rootfs.Path {
		return nil, fmt.Errorf("backend returned rootfs path outside original: %s", preparedPath)
	}

	// 5. Start networking.
	//
	// Default path: port forwards are passed to the runner, which creates
	// an in-process VirtualNetwork (gvisor-tap-vsock) alongside the VM.
	// This ensures networking lives as long as the runner process.
	//
	// Custom provider path: if WithNetProvider() was used, start the
	// external provider and pass its socket path to the runner instead.
	var netSocket string
	if cfg.netProvider != nil {
		slog.Debug("starting custom network provider")
		netCfg := cfg.buildNetConfig()
		if err := cfg.netProvider.Start(ctx, netCfg); err != nil {
			return nil, fmt.Errorf("networking: %w", err)
		}
		netSocket = cfg.netProvider.SocketPath()
	}

	// 6. Start VM via backend.
	slog.Debug("starting VM")
	var netEndpoint hypervisor.NetEndpoint
	if netSocket != "" {
		netEndpoint = hypervisor.NetEndpoint{Type: hypervisor.NetEndpointUnixSocket, Path: netSocket}
	}
	vmCfg := hypervisor.VMConfig{
		Name:             cfg.name,
		RootFSPath:       preparedPath,
		NumVCPUs:         cfg.cpus,
		RAMMiB:           cfg.memory,
		PortForwards:     toHypervisorPorts(cfg.ports),
		FilesystemMounts: toHypervisorMounts(cfg.virtioFS),
		InitConfig:       initCfg,
		DataDir:          cfg.dataDir,
		ConsoleLogPath:   filepath.Join(cfg.dataDir, "console.log"),
		NetEndpoint:      netEndpoint,
	}
	handle, err := backend.Start(ctx, vmCfg)
	if err != nil {
		if cfg.netProvider != nil {
			cfg.netProvider.Stop()
		}
		return nil, fmt.Errorf("spawn vm: %w", err)
	}

	vm := &VM{
		name:       cfg.name,
		handle:     handle,
		netProv:    cfg.netProvider,
		dataDir:    cfg.dataDir,
		rootfsPath: rootfs.Path,
		ports:      cfg.ports,
		cacheDir:   cacheDir(cfg),
		removeAll:  cfg.removeAll,
	}

	// Best-effort state persistence for crash recovery.
	// NOTE: we must release the lock before post-boot hooks run, because
	// a failing hook calls vm.Stop() which also acquires the state lock.
	// Using explicit Release() instead of defer to avoid deadlock.
	stateMgr := state.NewManager(cfg.dataDir)
	if ls, stateErr := stateMgr.LoadAndLock(ctx); stateErr == nil {
		ls.State.Active = true
		ls.State.Name = cfg.name
		if pid, pidErr := pidFromID(handle.ID()); pidErr == nil {
			ls.State.PID = pid
		} else {
			slog.Warn("could not persist VM PID", "id", handle.ID(), "error", pidErr)
		}
		ls.State.Image = imageRef
		ls.State.CPUs = cfg.cpus
		ls.State.MemoryMB = cfg.memory
		if saveErr := ls.Save(); saveErr != nil {
			slog.Warn("failed to persist VM state", "error", saveErr)
		}
		ls.Release()
	}

	// 7. Post-boot hooks (no-op on happy path).
	for _, hook := range cfg.postBootHooks {
		if err := hook(ctx, vm); err != nil {
			if stopErr := vm.Stop(ctx); stopErr != nil {
				slog.Warn("failed to stop VM after post-boot hook failure", "error", stopErr)
			}
			return nil, fmt.Errorf("post-boot hook: %w", err)
		}
	}

	slog.Info("VM running", "name", cfg.name, "id", handle.ID())
	return vm, nil
}

const (
	// staleTermTimeout is the maximum time to wait for a stale runner to
	// exit after SIGTERM before sending SIGKILL.
	staleTermTimeout = 5 * time.Second
	// staleTermPoll is the interval between liveness checks during stale
	// runner termination.
	staleTermPoll = 250 * time.Millisecond
)

func cleanDataDir(cfg *config) error {
	if cfg.dataDir == "" {
		return nil
	}
	_, err := cfg.stat(cfg.dataDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("check data dir: %w", err)
	}

	// Best-effort: terminate any stale runner process before wiping.
	terminateStaleRunner(cfg)

	var keep []string
	cache := cacheDir(cfg)
	if cache != "" && isWithin(cfg.dataDir, cache) {
		keep = append(keep, cache)
	}
	if cfg.rootfsPath != "" && isWithin(cfg.dataDir, cfg.rootfsPath) {
		keep = append(keep, cfg.rootfsPath)
	}
	if len(keep) > 0 {
		if err := removeDataDirContentsExcept(cfg.removeAll, cfg.dataDir, keep); err != nil {
			return fmt.Errorf("clean data dir contents: %w", err)
		}
		return nil
	}

	if err := cfg.removeAll(cfg.dataDir); err != nil {
		return fmt.Errorf("clean data dir: %w", err)
	}
	return nil
}

// terminateStaleRunner checks the state file in the data directory for a
// previously-running runner process. If the PID is alive, it sends SIGTERM
// and waits up to staleTermTimeout before sending SIGKILL. This prevents
// orphaned runner processes from holding KVM file descriptors and virtiofs
// mounts when the parent process was hard-killed.
func terminateStaleRunner(cfg *config) {
	mgr := state.NewManager(cfg.dataDir)
	st, err := mgr.Load()
	if err != nil {
		slog.Debug("could not load state for stale runner check", "error", err)
		return
	}
	if st.PID <= 1 {
		return
	}
	if !cfg.processAlive(st.PID) {
		slog.Debug("stale runner already dead", "pid", st.PID)
		return
	}

	// Use negative PID to signal the entire process group (PGID == PID
	// because the runner starts with Setsid: true). This ensures any
	// children spawned by the runner are also terminated.
	target := -st.PID

	slog.Warn("terminating stale runner process group", "pid", st.PID)
	if err := cfg.killProcess(target, syscall.SIGTERM); err != nil {
		slog.Warn("failed to send SIGTERM to stale runner", "pid", st.PID, "error", err)
		return
	}

	// Poll until the process exits or the timeout expires.
	deadline := time.Now().Add(staleTermTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(staleTermPoll)
		if !cfg.processAlive(st.PID) {
			slog.Info("stale runner terminated gracefully", "pid", st.PID)
			return
		}
	}

	// Force kill.
	slog.Warn("stale runner did not exit after SIGTERM, sending SIGKILL", "pid", st.PID)
	if err := cfg.killProcess(target, syscall.SIGKILL); err != nil {
		slog.Warn("failed to send SIGKILL to stale runner", "pid", st.PID, "error", err)
	}
}

// forceRemoveAll removes the given path, handling read-only directory trees
// such as Go module caches (whose entries are set to 0444/0555). It first
// attempts a plain os.RemoveAll; on failure it walks the tree making every
// directory user-writable, then retries.
func forceRemoveAll(path string) error {
	err := os.RemoveAll(path)
	if err == nil {
		return nil
	}

	// Make every directory writable so entries can be unlinked.
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // best-effort
		}
		if d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})

	return os.RemoveAll(path)
}

func cacheDir(cfg *config) string {
	if cfg == nil || cfg.imageCache == nil {
		return ""
	}
	return cfg.imageCache.BaseDir()
}

func buildInitConfig(ociCfg *image.OCIConfig, cfg *config) hypervisor.InitConfig {
	ic := hypervisor.InitConfig{
		WorkingDir: "/",
		Env:        []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}

	if ociCfg != nil {
		if ociCfg.WorkingDir != "" {
			ic.WorkingDir = ociCfg.WorkingDir
		}
		ic.Env = append(ic.Env, ociCfg.Env...)
		ic.Cmd = append(ociCfg.Entrypoint, ociCfg.Cmd...)
	}

	// InitOverride replaces whatever the OCI image specified.
	if len(cfg.initOverride) > 0 {
		ic.Cmd = cfg.initOverride
	}

	return ic
}

func toHypervisorPorts(ports []PortForward) []hypervisor.PortForward {
	out := make([]hypervisor.PortForward, len(ports))
	for i, p := range ports {
		out[i] = hypervisor.PortForward{Host: p.Host, Guest: p.Guest}
	}
	return out
}

func toHypervisorMounts(mounts []VirtioFSMount) []hypervisor.FilesystemMount {
	out := make([]hypervisor.FilesystemMount, len(mounts))
	for i, m := range mounts {
		out[i] = hypervisor.FilesystemMount{Tag: m.Tag, HostPath: m.HostPath}
	}
	return out
}

func pidFromID(id string) (int, error) {
	pid, err := strconv.Atoi(id)
	if err != nil {
		return 0, fmt.Errorf("parse VM ID %q as PID: %w", id, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("invalid PID %d from VM ID %q", pid, id)
	}
	return pid, nil
}
