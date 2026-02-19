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
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/net/firewall"
	"github.com/stacklok/propolis/net/hosted"
	"github.com/stacklok/propolis/runner"
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

	// 3. Run rootfs hooks (no-op on happy path).
	for _, hook := range cfg.rootfsHooks {
		if err := hook(rootfs.Path, rootfs.Config); err != nil {
			return nil, fmt.Errorf("rootfs hook: %w", err)
		}
	}

	// 4. Write .krun_config.json.
	krunCfg := buildKrunConfig(rootfs.Config, cfg)
	if err := krunCfg.WriteTo(rootfs.Path); err != nil {
		return nil, fmt.Errorf("write krun config: %w", err)
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

	// 6. Spawn VM runner subprocess.
	slog.Debug("spawning VM")
	runCfg := runner.Config{
		RootPath:     rootfs.Path,
		NumVCPUs:     cfg.cpus,
		RAMMiB:       cfg.memory,
		NetSocket:    netSocket,
		PortForwards: toRunnerPortForwards(cfg.ports),
		VirtioFS:     toRunnerVirtioFS(cfg.virtioFS),
		ConsoleLog:   filepath.Join(cfg.dataDir, "console.log"),
		LibDir:       cfg.libDir,
		RunnerPath:   cfg.runnerPath,
		VMLogPath:    filepath.Join(cfg.dataDir, "vm.log"),
	}

	spawner := cfg.spawner
	if spawner == nil {
		spawner = runner.DefaultSpawner{}
	}
	proc, err := spawner.Spawn(ctx, runCfg)
	if err != nil {
		if cfg.netProvider != nil {
			cfg.netProvider.Stop()
		}
		return nil, fmt.Errorf("spawn vm: %w", err)
	}

	vm := &VM{
		name:       cfg.name,
		proc:       proc,
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
		ls.State.PID = proc.PID()
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

	slog.Info("VM running", "name", cfg.name, "pid", proc.PID())
	return vm, nil
}

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

func cacheDir(cfg *config) string {
	if cfg == nil || cfg.imageCache == nil {
		return ""
	}
	return cfg.imageCache.BaseDir()
}

func toRunnerPortForwards(ports []PortForward) []runner.PortForward {
	out := make([]runner.PortForward, len(ports))
	for i, p := range ports {
		out[i] = runner.PortForward{Host: p.Host, Guest: p.Guest}
	}
	return out
}

func toRunnerVirtioFS(mounts []VirtioFSMount) []runner.VirtioFSMount {
	out := make([]runner.VirtioFSMount, len(mounts))
	for i, m := range mounts {
		out[i] = runner.VirtioFSMount{Tag: m.Tag, HostPath: m.HostPath}
	}
	return out
}

func buildKrunConfig(ociCfg *image.OCIConfig, cfg *config) image.KrunConfig {
	kc := image.KrunConfig{
		WorkingDir: "/",
		Env:        []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
	}

	if ociCfg != nil {
		if ociCfg.WorkingDir != "" {
			kc.WorkingDir = ociCfg.WorkingDir
		}
		kc.Env = append(kc.Env, ociCfg.Env...)
		kc.Cmd = append(ociCfg.Entrypoint, ociCfg.Cmd...)
	}

	// InitOverride replaces whatever the OCI image specified.
	if len(cfg.initOverride) > 0 {
		kc.Cmd = cfg.initOverride
	}

	return kc
}
