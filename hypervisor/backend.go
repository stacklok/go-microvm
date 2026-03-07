// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hypervisor

import "context"

// Backend abstracts the hypervisor used to run a microVM.
// Each implementation is responsible for preparing the root filesystem
// and starting the VM through its own mechanism.
type Backend interface {
	// Name returns a short identifier for this backend (e.g. "libkrun").
	Name() string
	// PrepareRootFS applies any backend-specific setup to the rootfs
	// directory (e.g. writing .krun_config.json for libkrun). It
	// returns the path to use as the VM root filesystem, which must
	// be equal to or within rootfsPath. Returning a path outside
	// rootfsPath is a contract violation that callers will reject.
	PrepareRootFS(ctx context.Context, rootfsPath string, initCfg InitConfig) (string, error)
	// Start launches the VM and returns a handle for lifecycle management.
	// If Start returns an error, the backend must have cleaned up any
	// partial state (e.g. killed partially-spawned processes). Callers
	// must not attempt recovery from partial start failures.
	Start(ctx context.Context, cfg VMConfig) (VMHandle, error)
}

// VMHandle provides lifecycle control over a running VM.
// All methods must be safe for concurrent use.
type VMHandle interface {
	// Stop gracefully shuts down the VM. Stop must be idempotent:
	// calling it on an already-stopped VM returns nil.
	Stop(ctx context.Context) error
	// IsAlive reports whether the VM is still running.
	IsAlive() bool
	// ID returns a backend-specific identifier for the VM (e.g. PID
	// for process-based backends, instance ID for cloud backends).
	// The returned value must be stable across calls.
	ID() string
}

// VMConfig contains all parameters needed to start a VM.
type VMConfig struct {
	Name             string
	RootFSPath       string
	NumVCPUs         uint32
	RAMMiB           uint32
	PortForwards     []PortForward
	FilesystemMounts []FilesystemMount
	InitConfig       InitConfig
	DataDir          string
	ConsoleLogPath   string
	LogLevel         uint32 // Hypervisor log level (0=off, 5=most verbose)
	NetEndpoint      NetEndpoint
}

// InitConfig describes the process to run inside the VM.
type InitConfig struct {
	Cmd        []string
	Env        []string
	WorkingDir string
}

// NetEndpoint describes how the VM connects to the network.
type NetEndpoint struct {
	Type NetEndpointType
	Path string
}

// NetEndpointType enumerates supported network transport mechanisms.
type NetEndpointType int

const (
	// NetEndpointNone means no external network endpoint is configured.
	NetEndpointNone NetEndpointType = iota
	// NetEndpointUnixSocket connects via a Unix domain socket.
	NetEndpointUnixSocket
	// NetEndpointNamedPipe connects via a named pipe (Windows).
	NetEndpointNamedPipe
	// NetEndpointHVSocket connects via a Hyper-V socket.
	NetEndpointHVSocket
)

// PortForward maps a host port to a guest port.
type PortForward struct {
	Host  uint16
	Guest uint16
}

// FilesystemMount exposes a host directory to the guest.
type FilesystemMount struct {
	Tag      string
	HostPath string
}
