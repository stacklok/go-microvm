// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build (linux || darwin) && cgo

// Package main provides the go-microvm-runner helper binary.
// This binary is spawned as a subprocess by the go-microvm framework
// to run VMs using libkrun's CGO bindings.
//
// IMPORTANT: libkrun's krun_start_enter() takes over the calling process
// and never returns on success. This is why we need a separate binary -
// we cannot call it from the main Go application without losing control.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"

	"github.com/stacklok/go-microvm/internal/logbridge"
	"github.com/stacklok/go-microvm/krun"
	"github.com/stacklok/go-microvm/net/topology"
)

// sentinel errors for classifying exit codes.
var (
	errLibkrunContext = errors.New("libkrun context creation failed")
	errStartupFailed  = errors.New("VM failed to start")
)

// PortForward describes a TCP port forwarding rule from host to guest.
type PortForward struct {
	Host  uint16 `json:"host"`
	Guest uint16 `json:"guest"`
}

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
	// NetSockPath is a Unix socket path for an external networking provider.
	// Mutually exclusive with PortForwards.
	NetSockPath string `json:"net_sock_path,omitempty"`
	// PortForwards configures in-process networking. When set and NetSockPath
	// is empty, the runner creates a VirtualNetwork and connects it via socketpair.
	PortForwards []PortForward `json:"port_forwards,omitempty"`
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
		fmt.Fprintf(os.Stderr, "\nThis is a helper binary for go-microvm.\n")
		fmt.Fprintf(os.Stderr, "It should not be run directly.\n")
		os.Exit(exitConfigError)
	}

	// Redirect gvisor-tap-vsock's logrus output through slog before any
	// networking is set up, so it doesn't pollute stderr.
	logbridge.RedirectLogrus()

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

	// Configure networking.
	switch {
	case config.NetSockPath != "":
		// External provider: connect to a pre-existing Unix socket.
		if err := ctx.AddNetUnixStream(-1, config.NetSockPath, nil, krun.CompatNetFeatures, 0); err != nil {
			_ = ctx.Free()
			return fmt.Errorf("add virtio-net (external socket): %w", err)
		}

	case len(config.PortForwards) > 0:
		// In-process networking: create a VirtualNetwork and connect via socketpair.
		vmFD, err := setupInProcessNetworking(config.PortForwards)
		if err != nil {
			_ = ctx.Free()
			return fmt.Errorf("setup in-process networking: %w", err)
		}
		if err := ctx.AddNetUnixStream(vmFD, "", nil, krun.CompatNetFeatures, 0); err != nil {
			_ = ctx.Free()
			_ = syscall.Close(vmFD)
			return fmt.Errorf("add virtio-net (in-process): %w", err)
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

// setupInProcessNetworking creates a gvisor-tap-vsock VirtualNetwork with
// the given port forwards and returns a file descriptor for the VM side
// of a socketpair. The VirtualNetwork runs in background goroutines that
// persist alongside krun_start_enter() until the process exits.
func setupInProcessNetworking(ports []PortForward) (int, error) {
	// Build port forward map: "127.0.0.1:<host>" -> "<guest>:<guest>"
	forwards := make(map[string]string, len(ports))
	for _, pf := range ports {
		hostAddr := fmt.Sprintf("127.0.0.1:%d", pf.Host)
		guestAddr := fmt.Sprintf("%s:%d", topology.GuestIP, pf.Guest)
		forwards[hostAddr] = guestAddr
	}

	// Create the virtual network stack.
	vn, err := virtualnetwork.New(&types.Configuration{
		Subnet:            topology.Subnet,
		GatewayIP:         topology.GatewayIP,
		GatewayMacAddress: topology.GatewayMAC,
		MTU:               topology.MTU,
		Forwards:          forwards,
	})
	if err != nil {
		return -1, fmt.Errorf("create virtual network: %w", err)
	}

	// Create a socketpair. One end goes to the VirtualNetwork (QEMU
	// transport), the other is passed to libkrun via its fd parameter.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return -1, fmt.Errorf("create socketpair: %w", err)
	}

	// Wrap the network side fd as a net.Conn for AcceptQemu.
	netFile := os.NewFile(uintptr(fds[0]), "vnet-network")
	netConn, err := net.FileConn(netFile)
	// FileConn dups the fd, so close the original.
	_ = netFile.Close()
	if err != nil {
		_ = syscall.Close(fds[1])
		return -1, fmt.Errorf("create net.Conn from socketpair: %w", err)
	}

	// Start AcceptQemu in a background goroutine. This goroutine will
	// run alongside krun_start_enter() on a separate OS thread and handle
	// all Ethernet frame I/O between the virtual network and the VM.
	go func() {
		if qErr := vn.AcceptQemu(context.Background(), netConn); qErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: virtual network ended: %v\n", qErr)
		}
	}()

	// Return the VM side fd. libkrun will use this directly via
	// krun_add_net_unixstream(fd, ...).
	return fds[1], nil
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
