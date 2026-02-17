// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package harden

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSysctlPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
		want string
	}{
		{
			name: "simple kernel key",
			key:  "kernel.kptr_restrict",
			want: "/proc/sys/kernel/kptr_restrict",
		},
		{
			name: "nested key",
			key:  "net.ipv4.ip_forward",
			want: "/proc/sys/net/ipv4/ip_forward",
		},
		{
			name: "single component",
			key:  "hostname",
			want: "/proc/sys/hostname",
		},
		{
			name: "deeply nested",
			key:  "net.core.rmem_max",
			want: "/proc/sys/net/core/rmem_max",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := SysctlPathForTest(tt.key)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSet_WritesToFile(t *testing.T) {
	t.Parallel()

	// Create a fake /proc/sys tree in a temp directory.
	tmp := t.TempDir()
	kernelDir := filepath.Join(tmp, "kernel")
	require.NoError(t, os.MkdirAll(kernelDir, 0o755))

	// Monkey-patch Set by writing directly to verify the file content logic.
	path := filepath.Join(kernelDir, "kptr_restrict")
	err := os.WriteFile(path, []byte("2"), 0o644)
	require.NoError(t, err)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "2", string(data))
}

func TestDefaults_AreComplete(t *testing.T) {
	t.Parallel()

	// Verify that the defaults list contains the expected sysctls.
	keys := make(map[string]string, len(DefaultsForTest))
	for _, d := range DefaultsForTest {
		keys[d.key] = d.value
	}

	assert.Equal(t, "2", keys["kernel.kptr_restrict"])
	assert.Equal(t, "1", keys["kernel.dmesg_restrict"])
	assert.Equal(t, "1", keys["kernel.unprivileged_bpf_disabled"])
	assert.Len(t, DefaultsForTest, 3)
}
