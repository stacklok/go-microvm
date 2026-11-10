// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hyperv

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/codes"

	"github.com/stacklok/go-microvm/extract"
	"github.com/stacklok/go-microvm/hypervisor"
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
	backend := &Backend{vhdBuilder: buildVHD}
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
	temporaryPath := outputPath + ".tmp"
	if err := backend.vhdBuilder(ctx, rootfsPath, temporaryPath); err != nil {
		_ = os.Remove(temporaryPath)
		return "", fmt.Errorf("build rootfs VHD: %w", err)
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		_ = os.Remove(temporaryPath)
		return "", fmt.Errorf("install rootfs VHD: %w", err)
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

func buildVHD(ctx context.Context, rootfsDir, outVHDPath string) error {
	output, err := os.OpenFile(outVHDPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("create output VHD: %w", err)
	}
	defer func() { _ = output.Close() }()

	reader, writer := io.Pipe()
	tarErr := make(chan error, 1)
	go func() {
		err := writeRootFSTar(ctx, writer, rootfsDir)
		_ = writer.CloseWithError(err)
		tarErr <- err
	}()

	convertErr := tar2ext4.Convert(reader, output, tar2ext4.AppendVhdFooter)
	if err := reader.Close(); err != nil && convertErr == nil {
		convertErr = err
	}
	archiveErr := <-tarErr
	if archiveErr != nil {
		return fmt.Errorf("archive rootfs: %w", archiveErr)
	}
	if convertErr != nil {
		return fmt.Errorf("convert rootfs archive: %w", convertErr)
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("sync output VHD: %w", err)
	}
	return nil
}

func writeRootFSTar(ctx context.Context, destination io.Writer, rootfsDir string) error {
	archive := tar.NewWriter(destination)
	err := filepath.WalkDir(rootfsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		relativePath, err := filepath.Rel(rootfsDir, path)
		if err != nil {
			return fmt.Errorf("resolve archive path: %w", err)
		}
		if relativePath == "." {
			return nil
		}
		archivePath := filepath.ToSlash(relativePath)
		if archivePath == rootVHDName || archivePath == rootVHDName+".tmp" {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", path, err)
		}
		linkTarget := ""
		if info.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(path)
			if err != nil {
				return fmt.Errorf("read symlink %s: %w", path, err)
			}
		}
		header, err := tar.FileInfoHeader(info, linkTarget)
		if err != nil {
			return fmt.Errorf("create tar header for %s: %w", path, err)
		}
		header.Name = archivePath
		if info.IsDir() && !strings.HasSuffix(header.Name, "/") {
			header.Name += "/"
		}
		if err := archive.WriteHeader(header); err != nil {
			return fmt.Errorf("write tar header for %s: %w", path, err)
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open %s: %w", path, err)
		}
		_, copyErr := io.Copy(archive, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("archive %s: %w", path, copyErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", path, closeErr)
		}
		return nil
	})
	if err != nil {
		_ = archive.Close()
		return err
	}
	if err := archive.Close(); err != nil {
		return fmt.Errorf("close rootfs archive: %w", err)
	}
	return nil
}
