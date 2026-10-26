// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_MarshalUnmarshal_RoundTrip(t *testing.T) {
	t.Parallel()

	original := Config{
		RootPath:  "/var/lib/go-microvm/rootfs",
		NumVCPUs:  4,
		RAMMiB:    1024,
		NetSocket: "/tmp/net.sock",
		VirtioFS: []VirtioFSMount{
			{Tag: "shared", HostPath: "/home/user/data"},
			{Tag: "readonly-data", HostPath: "/var/data", ReadOnly: true},
		},
		VsockPorts: []VsockPort{
			{Port: 1024, SocketPath: "/run/bbox/agent.sock"},
			{Port: 1025, SocketPath: "/run/bbox/io.sock"},
		},
		ConsoleLog: "/var/log/console.log",
		LogLevel:   3,
		// These should NOT appear in JSON.
		LibDir:     "/usr/local/lib/krun",
		RunnerPath: "/usr/bin/go-microvm-runner",
		VMLogPath:  "/var/log/vm.log",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var restored Config
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	// Serialized fields should match.
	assert.Equal(t, original.RootPath, restored.RootPath)
	assert.Equal(t, original.NumVCPUs, restored.NumVCPUs)
	assert.Equal(t, original.RAMMiB, restored.RAMMiB)
	assert.Equal(t, original.NetSocket, restored.NetSocket)
	assert.Equal(t, original.ConsoleLog, restored.ConsoleLog)
	assert.Equal(t, original.LogLevel, restored.LogLevel)
	require.Len(t, restored.VirtioFS, 2)
	assert.Equal(t, "shared", restored.VirtioFS[0].Tag)
	assert.Equal(t, "/home/user/data", restored.VirtioFS[0].HostPath)
	assert.False(t, restored.VirtioFS[0].ReadOnly)
	assert.Equal(t, "readonly-data", restored.VirtioFS[1].Tag)
	assert.Equal(t, "/var/data", restored.VirtioFS[1].HostPath)
	assert.True(t, restored.VirtioFS[1].ReadOnly)
	require.Len(t, restored.VsockPorts, 2)
	assert.Equal(t, uint32(1024), restored.VsockPorts[0].Port)
	assert.Equal(t, "/run/bbox/agent.sock", restored.VsockPorts[0].SocketPath)
	assert.Equal(t, uint32(1025), restored.VsockPorts[1].Port)
	assert.Equal(t, "/run/bbox/io.sock", restored.VsockPorts[1].SocketPath)

	// json:"-" fields should be zero in the unmarshaled result.
	assert.Empty(t, restored.LibDir)
	assert.Empty(t, restored.RunnerPath)
	assert.Empty(t, restored.VMLogPath)
}

func TestConfig_VsockPorts_OmitEmpty(t *testing.T) {
	t.Parallel()

	// With no VsockPorts, the JSON key must be omitted to preserve
	// backward-compatible JSON for the SSH-based brood-box path.
	cfg := Config{
		RootPath: "/rootfs",
		NumVCPUs: 1,
		RAMMiB:   512,
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)
	assert.NotContains(t, raw, "vsock_ports",
		"VsockPorts must be omitted from JSON when empty (backward compat)")
}

func TestVsockPort_JSON(t *testing.T) {
	t.Parallel()

	vp := VsockPort{Port: 1024, SocketPath: "/tmp/foo.sock"}
	data, err := json.Marshal(vp)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.Contains(t, raw, "port")
	assert.Contains(t, raw, "socket_path")

	var restored VsockPort
	require.NoError(t, json.Unmarshal(data, &restored))
	assert.Equal(t, vp, restored)
}

// runnerMainConfigMirror mirrors the Config struct defined in
// runner/cmd/go-microvm-runner/main.go. The duplication is intentional
// (see CLAUDE.md "runner config is duplicated") because the runner
// binary uses CGO and we don't want to pull a CGO dependency into the
// pure-Go runner/ package. This test exercises both structs against the
// same JSON to catch drift between them.
//
// When you add a new JSON field to runner.Config, you MUST also add it
// to runner/cmd/go-microvm-runner/main.go's Config struct AND mirror it
// here with the same JSON tag. CI will fail otherwise.
type runnerMainConfigMirror struct {
	RootPath     string `json:"root_path"`
	NumVCPUs     uint32 `json:"num_vcpus"`
	RAMMiB       uint32 `json:"ram_mib"`
	NetSockPath  string `json:"net_sock_path,omitempty"`
	PortForwards []struct {
		Host  uint16 `json:"host"`
		Guest uint16 `json:"guest"`
	} `json:"port_forwards,omitempty"`
	VirtioFSMounts []struct {
		Tag      string `json:"tag"`
		Path     string `json:"path"`
		ReadOnly bool   `json:"read_only,omitempty"`
	} `json:"virtiofs_mounts,omitempty"`
	VsockPorts []struct {
		Port       uint32 `json:"port"`
		SocketPath string `json:"socket_path"`
	} `json:"vsock_ports,omitempty"`
	ConsoleLogPath string `json:"console_log_path,omitempty"`
	LogLevel       uint32 `json:"log_level,omitempty"`
}

func TestConfig_RunnerMain_JSONCompatibility(t *testing.T) {
	t.Parallel()

	original := Config{
		RootPath:  "/rootfs",
		NumVCPUs:  2,
		RAMMiB:    1024,
		NetSocket: "/run/net.sock",
		PortForwards: []PortForward{
			{Host: 2222, Guest: 22},
		},
		VirtioFS: []VirtioFSMount{
			{Tag: "workspace", HostPath: "/host/work"},
			{Tag: "data", HostPath: "/host/data", ReadOnly: true},
		},
		VsockPorts: []VsockPort{
			{Port: 1024, SocketPath: "/run/agent.sock"},
		},
		ConsoleLog: "/var/log/console.log",
		LogLevel:   3,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var mirror runnerMainConfigMirror
	require.NoError(t, json.Unmarshal(data, &mirror),
		"JSON produced by runner.Config must decode into the runner main.go mirror")

	assert.Equal(t, original.RootPath, mirror.RootPath)
	assert.Equal(t, original.NumVCPUs, mirror.NumVCPUs)
	assert.Equal(t, original.RAMMiB, mirror.RAMMiB)
	assert.Equal(t, original.NetSocket, mirror.NetSockPath)

	require.Len(t, mirror.PortForwards, 1)
	assert.Equal(t, uint16(2222), mirror.PortForwards[0].Host)
	assert.Equal(t, uint16(22), mirror.PortForwards[0].Guest)

	require.Len(t, mirror.VirtioFSMounts, 2)
	assert.Equal(t, "workspace", mirror.VirtioFSMounts[0].Tag)
	assert.Equal(t, "/host/work", mirror.VirtioFSMounts[0].Path)
	assert.False(t, mirror.VirtioFSMounts[0].ReadOnly)
	assert.Equal(t, "data", mirror.VirtioFSMounts[1].Tag)
	assert.True(t, mirror.VirtioFSMounts[1].ReadOnly)

	require.Len(t, mirror.VsockPorts, 1)
	assert.Equal(t, uint32(1024), mirror.VsockPorts[0].Port)
	assert.Equal(t, "/run/agent.sock", mirror.VsockPorts[0].SocketPath)

	assert.Equal(t, original.ConsoleLog, mirror.ConsoleLogPath)
	assert.Equal(t, original.LogLevel, mirror.LogLevel)
}

func TestConfig_JSONDash_FieldsNotInOutput(t *testing.T) {
	t.Parallel()

	cfg := Config{
		RootPath:   "/rootfs",
		NumVCPUs:   2,
		RAMMiB:     512,
		LibDir:     "/lib/krun",
		RunnerPath: "/bin/runner",
		VMLogPath:  "/var/log/vm.log",
	}

	data, err := json.Marshal(cfg)
	require.NoError(t, err)

	// Parse as raw map to check key presence.
	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	// These keys should NOT be present (json:"-").
	assert.NotContains(t, raw, "LibDir")
	assert.NotContains(t, raw, "RunnerPath")
	assert.NotContains(t, raw, "VMLogPath")
	// Also check for any lowercase/snake_case variants.
	assert.NotContains(t, raw, "lib_dir")
	assert.NotContains(t, raw, "runner_path")
	assert.NotContains(t, raw, "vm_log_path")

	// These keys SHOULD be present.
	assert.Contains(t, raw, "root_path")
	assert.Contains(t, raw, "num_vcpus")
	assert.Contains(t, raw, "ram_mib")
}

func TestVirtioFSMount_Serialization(t *testing.T) {
	t.Parallel()

	mount := VirtioFSMount{
		Tag:      "workspace",
		HostPath: "/home/user/project",
	}

	data, err := json.Marshal(mount)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "tag")
	assert.Contains(t, raw, "path")
	// read_only should be omitted when false.
	assert.NotContains(t, raw, "read_only")

	var restored VirtioFSMount
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, mount.Tag, restored.Tag)
	assert.Equal(t, mount.HostPath, restored.HostPath)
	assert.False(t, restored.ReadOnly)
}

func TestVirtioFSMount_ReadOnly_Serialization(t *testing.T) {
	t.Parallel()

	mount := VirtioFSMount{
		Tag:      "data",
		HostPath: "/var/data",
		ReadOnly: true,
	}

	data, err := json.Marshal(mount)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "read_only")

	var restored VirtioFSMount
	err = json.Unmarshal(data, &restored)
	require.NoError(t, err)

	assert.Equal(t, mount.Tag, restored.Tag)
	assert.Equal(t, mount.HostPath, restored.HostPath)
	assert.True(t, restored.ReadOnly)
}

func TestConfig_Disks_JSON(t *testing.T) {
	t.Parallel()

	cfg := Config{
		RootPath: "/rootfs",
		Disks: []Disk{
			{ID: "data", HostPath: "/var/lib/vm/data.img", Format: "raw"},
			{ID: "seed", HostPath: "/var/lib/vm/seed.qcow2", Format: "qcow2", ReadOnly: true},
		},
	}
	data, err := json.Marshal(cfg)
	require.NoError(t, err)
	assert.Contains(t, string(data), `"disks":[{"block_id":"data","path":"/var/lib/vm/data.img","format":"raw"},`)

	var restored Config
	require.NoError(t, json.Unmarshal(data, &restored))
	assert.Equal(t, cfg.Disks, restored.Disks)
}

func TestConfig_Disks_OmitEmpty(t *testing.T) {
	t.Parallel()

	data, err := json.Marshal(Config{RootPath: "/rootfs"})
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))
	assert.NotContains(t, raw, "disks", "Disks must be omitted from JSON when empty")
}
