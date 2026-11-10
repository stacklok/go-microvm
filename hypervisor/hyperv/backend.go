// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hyperv

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"

	"github.com/stacklok/go-microvm/extract"
	"github.com/stacklok/go-microvm/hypervisor"
	"github.com/stacklok/go-microvm/image/vhd"
)

const (
	kernelFileName = "vmlinux"
	initrdFileName = "initrd.img"
	rootVHDName    = "rootfs.vhd"
)

// VHDBuilder builds a fixed VHD containing an ext4 filesystem.
type VHDBuilder func(ctx context.Context, rootfsDir, outVHDPath string) error

// Option configures a Hyper-V Backend.
type Option func(*Backend)

// WithKernelPath sets the direct-boot Linux kernel path.
func WithKernelPath(path string) Option {
	return func(backend *Backend) { backend.kernelPath = path }
}

// WithInitrdPath sets the optional direct-boot initrd path.
func WithInitrdPath(path string) Option {
	return func(backend *Backend) { backend.initrdPath = path }
}

// WithRunner sets the HCS lifecycle runner.
func WithRunner(runner Runner) Option {
	return func(backend *Backend) { backend.runner = runner }
}

// WithVHDBuilder sets the root filesystem VHD builder.
func WithVHDBuilder(builder VHDBuilder) Option {
	return func(backend *Backend) { backend.vhdBuilder = builder }
}

// WithRuntime sets a source containing vmlinux and an optional initrd.img.
func WithRuntime(source extract.Source) Option {
	return func(backend *Backend) { backend.runtime = source }
}

// WithCacheDir sets the runtime extraction cache directory.
func WithCacheDir(dir string) Option {
	return func(backend *Backend) { backend.cacheDir = dir }
}

// Backend implements hypervisor.Backend using Hyper-V HCS v2.
type Backend struct {
	kernelPath string
	initrdPath string
	runner     Runner
	vhdBuilder VHDBuilder
	runtime    extract.Source
	cacheDir   string
}

var _ hypervisor.Backend = (*Backend)(nil)

// NewBackend creates a Hyper-V backend with the given options.
func NewBackend(opts ...Option) *Backend {
	backend := &Backend{
		vhdBuilder: func(ctx context.Context, rootfsDir, outVHDPath string) error {
			return vhd.BuildFromDir(ctx, rootfsDir, outVHDPath)
		},
	}
	for _, option := range opts {
		option(backend)
	}
	return backend
}

// Name returns "hyperv".
func (backend *Backend) Name() string { return "hyperv" }

// PrepareRootFS writes the guest init config and converts the rootfs to a fixed VHD.
func (backend *Backend) PrepareRootFS(
	ctx context.Context,
	rootfsPath string,
	initCfg hypervisor.InitConfig,
) (string, error) {
	if err := writeKrunConfig(rootfsPath, initCfg); err != nil {
		return "", fmt.Errorf("write krun config: %w", err)
	}

	outputPath := filepath.Join(rootfsPath, rootVHDName)
	if err := backend.vhdBuilder(ctx, rootfsPath, outputPath); err != nil {
		return "", fmt.Errorf("build rootfs VHD: %w", err)
	}
	return outputPath, nil
}

// Start creates and starts a Hyper-V compute system.
func (backend *Backend) Start(ctx context.Context, cfg hypervisor.VMConfig) (hypervisor.VMHandle, error) {
	tracer := otel.Tracer("github.com/stacklok/go-microvm")
	ctx, span := tracer.Start(ctx, "microvm.backend.Start")
	defer span.End()

	if err := backend.validate(); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}

	kernelPath, initrdPath, err := backend.resolveBootFiles(ctx, cfg.DataDir)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, err
	}
	doc, err := BuildComputeSystemDoc(cfg, kernelPath, initrdPath)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("build compute system document: %w", err)
	}

	runner := backend.runner
	if runner == nil {
		runner = defaultRunner{}
	}
	vmID := cfg.Name
	if vmID == "" {
		vmID = defaultOwner
	}
	handle, err := runner.CreateAndStart(ctx, vmID, doc)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return nil, fmt.Errorf("create and start compute system: %w", err)
	}
	return &vmHandle{handle: handle}, nil
}

func (backend *Backend) validate() error {
	hasExplicitBootFiles := backend.kernelPath != "" || backend.initrdPath != ""
	if backend.runtime != nil && hasExplicitBootFiles {
		return fmt.Errorf("hyperv backend: WithRuntime and explicit boot file paths are mutually exclusive")
	}
	if backend.vhdBuilder == nil {
		return fmt.Errorf("hyperv backend: VHD builder must not be nil")
	}
	return nil
}

func (backend *Backend) resolveBootFiles(ctx context.Context, dataDir string) (string, string, error) {
	if backend.runtime != nil {
		runtimeDir, err := backend.runtime.Ensure(ctx, backend.cacheDir)
		if err != nil {
			return "", "", fmt.Errorf("resolve runtime: %w", err)
		}
		kernelPath := filepath.Join(runtimeDir, kernelFileName)
		if err := requireRegularFile(kernelPath); err != nil {
			return "", "", fmt.Errorf("resolve runtime kernel: %w", err)
		}
		return kernelPath, optionalRegularFile(filepath.Join(runtimeDir, initrdFileName)), nil
	}
	if backend.kernelPath != "" {
		return backend.kernelPath, backend.initrdPath, nil
	}

	kernelPath := filepath.Join(dataDir, kernelFileName)
	if err := requireRegularFile(kernelPath); err != nil {
		return "", "", fmt.Errorf("resolve kernel: %w", err)
	}
	initrdPath := backend.initrdPath
	if initrdPath == "" {
		initrdPath = optionalRegularFile(filepath.Join(dataDir, initrdFileName))
	}
	return kernelPath, initrdPath, nil
}

func requireRegularFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

func optionalRegularFile(path string) string {
	if err := requireRegularFile(path); err != nil {
		return ""
	}
	return path
}
