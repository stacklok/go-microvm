// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

// PortForward describes a TCP port forwarding rule from host to guest.
type PortForward struct {
	// Host is the port on the host side (127.0.0.1).
	Host uint16 `json:"host"`
	// Guest is the port inside the guest VM.
	Guest uint16 `json:"guest"`
}

// Config contains the configuration for running a VM via the propolis-runner subprocess.
type Config struct {
	// RootPath is the path to the root filesystem directory (virtiofs).
	RootPath string `json:"root_path"`
	// NumVCPUs is the number of virtual CPUs.
	NumVCPUs uint32 `json:"num_vcpus"`
	// RAMMiB is the amount of RAM in MiB.
	RAMMiB uint32 `json:"ram_mib"`
	// NetSocket is a Unix socket path for an external networking provider.
	// When set, the socket is passed to krun_add_net_unixstream via its
	// path parameter (fd=-1). Mutually exclusive with PortForwards.
	NetSocket string `json:"net_sock_path,omitempty"`
	// PortForwards configures in-process networking with the specified
	// TCP port forwards. When set and NetSocket is empty, the runner
	// creates an in-process gvisor-tap-vsock VirtualNetwork and connects
	// it to the VM via a socketpair. Mutually exclusive with NetSocket.
	PortForwards []PortForward `json:"port_forwards,omitempty"`
	// VirtioFS contains virtio-fs mounts to expose host directories to the guest.
	VirtioFS []VirtioFSMount `json:"virtiofs_mounts,omitempty"`
	// ConsoleLog is the path to write console output (optional).
	ConsoleLog string `json:"console_log_path,omitempty"`
	// LogLevel sets the libkrun log verbosity (0-5).
	LogLevel uint32 `json:"log_level,omitempty"`
	// LibDir is the path to a directory containing libkrun/libkrunfw shared
	// libraries. The runner subprocess uses this via LD_LIBRARY_PATH.
	// Not serialized to JSON; set by the caller before spawning.
	LibDir string `json:"-"`
	// RunnerPath is the explicit path to the propolis-runner binary.
	// Not serialized to JSON; used by Spawn to locate the binary.
	RunnerPath string `json:"-"`
	// VMLogPath is the path to the file where runner stdout/stderr is written.
	// Not serialized to JSON; used by Spawn to redirect output.
	VMLogPath string `json:"-"`
}

// VirtioFSMount exposes a host directory to the guest via virtio-fs.
type VirtioFSMount struct {
	// Tag is the filesystem tag visible in the guest.
	Tag string `json:"tag"`
	// HostPath is the host directory path.
	HostPath string `json:"path"`
}
