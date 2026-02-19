// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package libkrun

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/stacklok/propolis/hypervisor"
	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/runner"
)

// Option configures a libkrun Backend.
type Option func(*Backend)

// WithRunnerPath sets the path to the propolis-runner binary.
// When empty, the runner is found via $PATH or alongside the calling binary.
func WithRunnerPath(p string) Option { return func(b *Backend) { b.runnerPath = p } }

// WithLibDir sets the path to a directory containing libkrun/libkrunfw
// shared libraries. The runner subprocess will use this via LD_LIBRARY_PATH.
func WithLibDir(d string) Option { return func(b *Backend) { b.libDir = d } }

// WithSpawner sets a custom spawner for the runner subprocess.
// When nil (default), the standard runner.DefaultSpawner is used.
func WithSpawner(s runner.Spawner) Option { return func(b *Backend) { b.spawner = s } }

// Backend implements hypervisor.Backend using libkrun.
type Backend struct {
	runnerPath string
	libDir     string
	spawner    runner.Spawner
}

// NewBackend creates a libkrun backend with the given options.
func NewBackend(opts ...Option) *Backend {
	b := &Backend{}
	for _, o := range opts {
		o(b)
	}
	return b
}

// Name returns "libkrun".
func (b *Backend) Name() string { return "libkrun" }

// PrepareRootFS writes .krun_config.json into the rootfs directory.
func (b *Backend) PrepareRootFS(_ context.Context, rootfsPath string, initCfg hypervisor.InitConfig) (string, error) {
	kc := image.KrunConfig{
		Cmd:        initCfg.Cmd,
		Env:        initCfg.Env,
		WorkingDir: initCfg.WorkingDir,
	}
	if err := kc.WriteTo(rootfsPath); err != nil {
		return "", fmt.Errorf("write krun config: %w", err)
	}
	return rootfsPath, nil
}

// Start launches the VM via the propolis-runner subprocess.
func (b *Backend) Start(ctx context.Context, cfg hypervisor.VMConfig) (hypervisor.VMHandle, error) {
	var netSocket string
	if cfg.NetEndpoint.Type == hypervisor.NetEndpointUnixSocket {
		netSocket = cfg.NetEndpoint.Path
	}

	runCfg := runner.Config{
		RootPath:     cfg.RootFSPath,
		NumVCPUs:     cfg.NumVCPUs,
		RAMMiB:       cfg.RAMMiB,
		NetSocket:    netSocket,
		PortForwards: toRunnerPortForwards(cfg.PortForwards),
		VirtioFS:     toRunnerVirtioFS(cfg.FilesystemMounts),
		ConsoleLog:   cfg.ConsoleLogPath,
		LibDir:       b.libDir,
		RunnerPath:   b.runnerPath,
		VMLogPath:    filepath.Join(cfg.DataDir, "vm.log"),
	}

	spawner := b.spawner
	if spawner == nil {
		spawner = runner.DefaultSpawner{}
	}

	proc, err := spawner.Spawn(ctx, runCfg)
	if err != nil {
		return nil, fmt.Errorf("spawn runner: %w", err)
	}

	return &processHandle{proc: proc}, nil
}

func toRunnerPortForwards(ports []hypervisor.PortForward) []runner.PortForward {
	out := make([]runner.PortForward, len(ports))
	for i, p := range ports {
		out[i] = runner.PortForward{Host: p.Host, Guest: p.Guest}
	}
	return out
}

func toRunnerVirtioFS(mounts []hypervisor.FilesystemMount) []runner.VirtioFSMount {
	out := make([]runner.VirtioFSMount, len(mounts))
	for i, m := range mounts {
		out[i] = runner.VirtioFSMount{Tag: m.Tag, HostPath: m.HostPath}
	}
	return out
}
