// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package libkrun

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stacklok/go-microvm/extract"
	"github.com/stacklok/go-microvm/hypervisor"
	"github.com/stacklok/go-microvm/image"
	"github.com/stacklok/go-microvm/runner"
)

// Option configures a libkrun Backend.
type Option func(*Backend)

// WithRunnerPath sets the path to the go-microvm-runner binary.
// When empty, the runner is found via $PATH or alongside the calling binary.
func WithRunnerPath(p string) Option { return func(b *Backend) { b.runnerPath = p } }

// WithLibDir sets the path to a directory containing libkrun/libkrunfw
// shared libraries. The runner subprocess will use this via LD_LIBRARY_PATH.
func WithLibDir(d string) Option { return func(b *Backend) { b.libDir = d } }

// WithSpawner sets a custom spawner for the runner subprocess.
// When nil (default), the standard runner.DefaultSpawner is used.
func WithSpawner(s runner.Spawner) Option { return func(b *Backend) { b.spawner = s } }

// WithRuntime sets a Source that provides go-microvm-runner and libkrun.
// Mutually exclusive with WithRunnerPath and WithLibDir.
// When using bundle-based sources, WithCacheDir must also be set.
func WithRuntime(src extract.Source) Option { return func(b *Backend) { b.runtime = src } }

// WithFirmware sets a Source that provides libkrunfw.
// The firmware directory is appended to the library search path.
// When used with WithLibDir, the firmware directory is appended after it.
// When using bundle-based sources, WithCacheDir must also be set.
func WithFirmware(src extract.Source) Option { return func(b *Backend) { b.firmware = src } }

// WithCacheDir sets the directory used by bundle-based Sources for extraction.
// Ignored when Sources are directory-based.
func WithCacheDir(dir string) Option { return func(b *Backend) { b.cacheDir = dir } }

// WithUserNamespaceUID configures the runner to spawn inside a Linux user
// namespace (CLONE_NEWUSER) with a single UID/GID mapping. The child
// process gains CAP_SETUID and CAP_SETGID within the namespace, which
// allows libkrun's virtiofs passthrough to call set_creds() without
// requiring host-level capabilities.
//
// uid and gid specify the namespace-side IDs that map to the host
// process's real UID/GID. For example, if the guest expects UID 1000
// and the host runs as UID 1000, pass uid=1000, gid=1000.
//
// On non-Linux platforms, this option is accepted but has no effect.
func WithUserNamespaceUID(uid, gid uint32) Option {
	return func(b *Backend) {
		b.userNamespace = &runner.UserNamespaceConfig{UID: uid, GID: gid}
	}
}

// Backend implements hypervisor.Backend using libkrun.
type Backend struct {
	runnerPath    string
	libDir        string
	spawner       runner.Spawner
	runtime       extract.Source
	firmware      extract.Source
	cacheDir      string
	userNamespace *runner.UserNamespaceConfig
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

// validate checks for conflicting option combinations.
func (b *Backend) validate() error {
	if b.runtime != nil && b.runnerPath != "" {
		return fmt.Errorf("libkrun backend: WithRuntime and WithRunnerPath are mutually exclusive")
	}
	if b.runtime != nil && b.libDir != "" {
		return fmt.Errorf("libkrun backend: WithRuntime and WithLibDir are mutually exclusive")
	}
	return nil
}

// Start launches the VM via the go-microvm-runner subprocess.
func (b *Backend) Start(ctx context.Context, cfg hypervisor.VMConfig) (hypervisor.VMHandle, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}

	runnerPath := b.runnerPath
	libDir := b.libDir

	if b.runtime != nil {
		runtimeDir, err := b.runtime.Ensure(ctx, b.cacheDir)
		if err != nil {
			return nil, fmt.Errorf("resolve runtime: %w", err)
		}
		candidate := filepath.Join(runtimeDir, extract.RunnerBinaryName)
		if _, err := os.Stat(candidate); err != nil {
			return nil, fmt.Errorf("resolve runtime: %s not found at %s: %w", extract.RunnerBinaryName, candidate, err)
		}
		runnerPath = candidate
		libDir = runtimeDir
	}

	if b.firmware != nil {
		fwDir, err := b.firmware.Ensure(ctx, b.cacheDir)
		if err != nil {
			return nil, fmt.Errorf("resolve firmware: %w", err)
		}
		if libDir != "" {
			libDir = libDir + string(os.PathListSeparator) + fwDir
		} else {
			libDir = fwDir
		}
	}

	var netSocket string
	if cfg.NetEndpoint.Type == hypervisor.NetEndpointUnixSocket {
		netSocket = cfg.NetEndpoint.Path
	}

	runCfg := runner.Config{
		RootPath:      cfg.RootFSPath,
		NumVCPUs:      cfg.NumVCPUs,
		RAMMiB:        cfg.RAMMiB,
		NetSocket:     netSocket,
		PortForwards:  toRunnerPortForwards(cfg.PortForwards),
		VirtioFS:      toRunnerVirtioFS(cfg.FilesystemMounts),
		ConsoleLog:    cfg.ConsoleLogPath,
		LogLevel:      cfg.LogLevel,
		LibDir:        libDir,
		RunnerPath:    runnerPath,
		VMLogPath:     filepath.Join(cfg.DataDir, "vm.log"),
		UserNamespace: b.userNamespace,
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
