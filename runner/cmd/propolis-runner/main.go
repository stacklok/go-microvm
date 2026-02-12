// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package main provides the propolis-runner helper binary.
// This binary is spawned as a subprocess by the propolis framework
// to run VMs using libkrun's CGO bindings.
//
// IMPORTANT: libkrun's krun_start_enter() takes over the calling process
// and never returns on success. This is why we need a separate binary -
// we cannot call it from the main Go application without losing control.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stacklok/propolis/krun"
)

// sentinel errors for classifying exit codes.
var (
	errLibkrunContext = errors.New("libkrun context creation failed")
	errStartupFailed  = errors.New("VM failed to start")
)

// Config contains the configuration for running a VM.
// This is passed as a JSON argument to the helper binary.
// The fields match runner.Config's JSON serialization.
type Config struct {
	// RootPath is the path to the root filesystem directory (virtiofs).
	RootPath string `json:"root_path"`
	// NumVCPUs is the number of virtual CPUs.
	NumVCPUs uint32 `json:"num_vcpus"`
	// RAMMiB is the amount of RAM in MiB.
	RAMMiB uint32 `json:"ram_mib"`
	// NetSockPath is a Unix socket path for virtio-net (gvproxy).
	// When set, the socket is passed to krun_add_net_unixstream via its
	// path parameter (fd=-1).
	NetSockPath string `json:"net_sock_path,omitempty"`
	// VirtioFSMounts contains virtio-fs mounts as tag:path entries.
	VirtioFSMounts []VirtioFSMount `json:"virtiofs_mounts,omitempty"`
	// ConsoleLogPath is the path to write console output (optional).
	ConsoleLogPath string `json:"console_log_path,omitempty"`
	// LogLevel sets the libkrun log verbosity (0-5).
	LogLevel uint32 `json:"log_level,omitempty"`
}

// VirtioFSMount represents a virtio-fs mount point.
type VirtioFSMount struct {
	// Tag is the filesystem tag visible in the guest.
	Tag string `json:"tag"`
	// Path is the host directory path.
	Path string `json:"path"`
}

// Exit codes for the runner binary.
const (
	exitSuccess      = 0
	exitConfigError  = 125
	exitRuntimeError = 1
	exitStartupError = 2
	exitLibkrunError = 3
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <config-json>\n", filepath.Base(os.Args[0]))
		fmt.Fprintf(os.Stderr, "\nThis is a helper binary for propolis.\n")
		fmt.Fprintf(os.Stderr, "It should not be run directly.\n")
		os.Exit(exitConfigError)
	}

	// Parse configuration from JSON argument.
	var config Config
	if err := json.Unmarshal([]byte(os.Args[1]), &config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to parse config JSON: %v\n", err)
		os.Exit(exitConfigError)
	}

	// Validate configuration.
	if err := validateConfig(&config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid configuration: %v\n", err)
		os.Exit(exitConfigError)
	}

	// Run the VM.
	if err := runVM(&config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to run VM: %v\n", err)
		os.Exit(exitCodeForError(err))
	}

	// If we get here, something went wrong (krun_start_enter should never return on success).
	fmt.Fprintf(os.Stderr, "Error: VM exited unexpectedly\n")
	os.Exit(exitRuntimeError)
}

func validateConfig(config *Config) error {
	if config.RootPath == "" {
		return fmt.Errorf("root_path is required")
	}
	if config.NumVCPUs == 0 {
		return fmt.Errorf("num_vcpus must be > 0")
	}
	if config.RAMMiB == 0 {
		return fmt.Errorf("ram_mib must be > 0")
	}

	// Check if root directory exists.
	info, err := os.Stat(config.RootPath)
	if err != nil {
		return fmt.Errorf("root path not found: %s: %w", config.RootPath, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("root path is not a directory: %s", config.RootPath)
	}

	return nil
}

func runVM(config *Config) error {
	// Set log level if specified.
	if config.LogLevel > 0 {
		if err := krun.SetLogLevel(krun.LogLevel(config.LogLevel)); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to set log level: %v\n", err)
		}
	}

	// Create libkrun context.
	ctx, err := krun.CreateContext()
	if err != nil {
		return fmt.Errorf("%w: %w", errLibkrunContext, err)
	}
	// Note: we don't defer ctx.Free() because krun_start_enter takes ownership.

	// Configure VM resources.
	if config.NumVCPUs > 255 {
		_ = ctx.Free()
		return fmt.Errorf("num_vcpus exceeds maximum (255): %d", config.NumVCPUs)
	}
	if err := ctx.SetVMConfig(uint8(config.NumVCPUs), config.RAMMiB); err != nil {
		_ = ctx.Free()
		return fmt.Errorf("set VM config: %w", err)
	}

	// Set the root filesystem directory (virtiofs).
	if err := ctx.SetRoot(config.RootPath); err != nil {
		_ = ctx.Free()
		return fmt.Errorf("set root: %w", err)
	}

	// NOTE: We do NOT call SetExec() here.
	// libkrun's built-in init process reads /.krun_config.json from the rootfs
	// to determine what program to execute. This is the approach used by krunvm.

	// Configure networking: virtio-net via gvproxy or TSI port mapping.
	if config.NetSockPath != "" {
		// gvproxy QEMU mode: SOCK_STREAM with 4-byte BE length-prefixed frames.
		// flags must be 0 for unixstream (no flags supported).
		if err := ctx.AddNetUnixStream(-1, config.NetSockPath, nil, krun.CompatNetFeatures, 0); err != nil {
			_ = ctx.Free()
			return fmt.Errorf("add virtio-net (gvproxy): %w", err)
		}
	}

	// Configure virtio-fs mounts.
	for _, mount := range config.VirtioFSMounts {
		if err := ctx.AddVirtioFS(mount.Tag, mount.Path); err != nil {
			_ = ctx.Free()
			return fmt.Errorf("add virtiofs mount %s: %w", mount.Tag, err)
		}
	}

	// Configure console output.
	if config.ConsoleLogPath != "" {
		if err := ctx.SetConsoleOutput(config.ConsoleLogPath); err != nil {
			_ = ctx.Free()
			return fmt.Errorf("set console output: %w", err)
		}
	}

	// Start the VM.
	// IMPORTANT: This call NEVER returns on success.
	// The process becomes the VM supervisor and will exit() when the VM shuts down.
	if err := ctx.StartEnter(); err != nil {
		return fmt.Errorf("%w: %w", errStartupFailed, err)
	}

	// Should never reach here.
	return fmt.Errorf("unexpected return from krun_start_enter")
}

// exitCodeForError maps known error types to specific exit codes for
// diagnostics. The caller can inspect the process exit code to distinguish
// between configuration errors, libkrun failures, and VM startup failures.
func exitCodeForError(err error) int {
	switch {
	case errors.Is(err, errLibkrunContext):
		return exitLibkrunError
	case errors.Is(err, errStartupFailed):
		return exitStartupError
	default:
		return exitRuntimeError
	}
}
