// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package image

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKrunConfig_WriteTo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config KrunConfig
	}{
		{
			name: "empty cmd",
			config: KrunConfig{
				Cmd:        nil,
				Env:        nil,
				WorkingDir: "/",
			},
		},
		{
			name: "non-empty cmd",
			config: KrunConfig{
				Cmd:        []string{"/bin/sh", "-c", "echo hello"},
				Env:        nil,
				WorkingDir: "/",
			},
		},
		{
			name: "with env vars",
			config: KrunConfig{
				Cmd:        []string{"/usr/bin/app"},
				Env:        []string{"FOO=bar", "PATH=/usr/bin"},
				WorkingDir: "/app",
			},
		},
		{
			name: "custom working dir",
			config: KrunConfig{
				Cmd:        []string{"/start.sh"},
				Env:        []string{"HOME=/home/user"},
				WorkingDir: "/home/user",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()

			err := tt.config.WriteTo(tmpDir)
			require.NoError(t, err)

			// Verify the file was created at the expected path.
			configPath := filepath.Join(tmpDir, krunConfigFile)
			data, err := os.ReadFile(configPath)
			require.NoError(t, err)

			// Verify it is valid JSON.
			var got KrunConfig
			err = json.Unmarshal(data, &got)
			require.NoError(t, err)

			// Verify round-trip fidelity.
			assert.Equal(t, tt.config.Cmd, got.Cmd)
			assert.Equal(t, tt.config.Env, got.Env)
			assert.Equal(t, tt.config.WorkingDir, got.WorkingDir)
		})
	}
}

func TestKrunConfig_WriteTo_JSONStructure(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	kc := KrunConfig{
		Cmd:        []string{"/bin/sh"},
		Env:        []string{"A=1"},
		WorkingDir: "/tmp",
	}

	err := kc.WriteTo(tmpDir)
	require.NoError(t, err)

	data, err := os.ReadFile(filepath.Join(tmpDir, krunConfigFile))
	require.NoError(t, err)

	// Verify the JSON keys match expected names.
	var raw map[string]json.RawMessage
	err = json.Unmarshal(data, &raw)
	require.NoError(t, err)

	assert.Contains(t, raw, "Cmd")
	assert.Contains(t, raw, "Env")
	assert.Contains(t, raw, "WorkingDir")
}

func TestKrunConfig_WriteTo_InvalidPath(t *testing.T) {
	t.Parallel()

	kc := KrunConfig{
		Cmd:        []string{"/bin/sh"},
		WorkingDir: "/",
	}

	err := kc.WriteTo("/nonexistent/path/that/does/not/exist")
	assert.Error(t, err)
}
