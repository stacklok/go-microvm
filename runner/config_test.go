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

	// json:"-" fields should be zero in the unmarshaled result.
	assert.Empty(t, restored.LibDir)
	assert.Empty(t, restored.RunnerPath)
	assert.Empty(t, restored.VMLogPath)
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
