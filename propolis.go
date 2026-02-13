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

	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/net/gvproxy"
	"github.com/stacklok/propolis/runner"
	"github.com/stacklok/propolis/state"
)

const (
	// defaultNetProviderBinary is the binary name used for auto-discovery
	// of the network provider next to the runner binary.
	defaultNetProviderBinary = "gvproxy"
)

// Run pulls an OCI image and boots it as a microVM. It is the primary entry
// point for the happy path. For more control, use [Create] followed by
// explicit lifecycle management.
func Run(ctx context.Context, imageRef string, opts ...Option) (*VM, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		opt.apply(cfg)
	}

	if err := os.MkdirAll(cfg.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
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

	// 5. Start networking (lazy-init default provider if not set by caller).
	//
	// Resolution order:
	//   1. WithNetProvider(p) — fully custom provider (unchanged)
	//   2. WithNetProviderBinaryPath(path) — explicit binary path
	//   3. Auto-discover: look for gvproxy next to the runner binary
	//   4. gvproxy.New() — PATH search fallback
	if cfg.netProvider == nil {
		binaryPath := ""
		if cfg.netProviderBinaryPath != "" {
			binaryPath = cfg.netProviderBinaryPath
		} else if cfg.runnerPath != "" {
			candidate := filepath.Join(filepath.Dir(cfg.runnerPath), defaultNetProviderBinary)
			if info, err := os.Stat(candidate); err == nil &&
				info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				binaryPath = candidate
			}
		}
		if binaryPath != "" {
			cfg.netProvider = gvproxy.NewWithBinaryPath(binaryPath, cfg.dataDir)
		} else {
			cfg.netProvider = gvproxy.New(cfg.dataDir)
		}
	}
	slog.Debug("starting network provider")
	netCfg := cfg.buildNetConfig()
	if err := cfg.netProvider.Start(ctx, netCfg); err != nil {
		return nil, fmt.Errorf("networking: %w", err)
	}

	// 6. Spawn VM runner subprocess.
	slog.Debug("spawning VM")
	runCfg := runner.Config{
		RootPath:   rootfs.Path,
		NumVCPUs:   cfg.cpus,
		RAMMiB:     cfg.memory,
		NetSocket:  cfg.netProvider.SocketPath(),
		VirtioFS:   toRunnerVirtioFS(cfg.virtioFS),
		ConsoleLog: filepath.Join(cfg.dataDir, "console.log"),
		LibDir:     cfg.libDir,
		RunnerPath: cfg.runnerPath,
		VMLogPath:  filepath.Join(cfg.dataDir, "vm.log"),
	}

	spawner := cfg.spawner
	if spawner == nil {
		spawner = runner.DefaultSpawner{}
	}
	proc, err := spawner.Spawn(ctx, runCfg)
	if err != nil {
		cfg.netProvider.Stop()
		return nil, fmt.Errorf("spawn vm: %w", err)
	}

	vm := &VM{
		name:       cfg.name,
		proc:       proc,
		netProv:    cfg.netProvider,
		dataDir:    cfg.dataDir,
		rootfsPath: rootfs.Path,
		ports:      cfg.ports,
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
		ls.State.NetProviderPID = cfg.netProvider.PID()
		ls.State.NetProviderBinary = cfg.netProvider.BinaryPath()
		_ = ls.Save()
		ls.Release()
	}

	// 7. Post-boot hooks (no-op on happy path).
	for _, hook := range cfg.postBootHooks {
		if err := hook(ctx, vm); err != nil {
			_ = vm.Stop(ctx)
			return nil, fmt.Errorf("post-boot hook: %w", err)
		}
	}

	slog.Info("VM running", "name", cfg.name, "pid", proc.PID())
	return vm, nil
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
