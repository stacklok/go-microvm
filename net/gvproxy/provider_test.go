// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package gvproxy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/net"
)

func TestNew_SetsDataDir(t *testing.T) {
	t.Parallel()

	p := New("/tmp/test-data")
	assert.Equal(t, "/tmp/test-data", p.dataDir)
}

func TestNewWithBinaryPath_SetsFields(t *testing.T) {
	t.Parallel()

	p := NewWithBinaryPath("/usr/local/bin/gvproxy", "/tmp/test-data")

	assert.Equal(t, "/usr/local/bin/gvproxy", p.binaryPath)
	assert.Equal(t, "/tmp/test-data", p.dataDir)
}

func TestNewWithBinaryPath_SkipsLookPath(t *testing.T) {
	t.Parallel()

	// NewWithBinaryPath should use the path as-is, even if the binary
	// doesn't actually exist at that path.
	p := NewWithBinaryPath("/nonexistent/gvproxy", "/tmp/data")

	assert.Equal(t, "/nonexistent/gvproxy", p.binaryPath)
}

func TestWriteConfig_NoPorts(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	p := &Provider{
		sockPath:   filepath.Join(tmpDir, "gvproxy.sock"),
		configPath: filepath.Join(tmpDir, "gvproxy.yaml"),
	}

	err := p.writeConfig(nil)
	require.NoError(t, err)

	data, err := os.ReadFile(p.configPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, "interfaces:")
	assert.Contains(t, content, "qemu: unix://")
	assert.Contains(t, content, "stack:")
	assert.Contains(t, content, "forwards:")
}

func TestWriteConfig_WithPorts(t *testing.T) {
	t.Parallel()
	tmpDir := t.TempDir()
	p := &Provider{
		sockPath:   filepath.Join(tmpDir, "gvproxy.sock"),
		configPath: filepath.Join(tmpDir, "gvproxy.yaml"),
	}

	ports := []net.PortForward{
		{Host: 8080, Guest: 80},
		{Host: 2222, Guest: 22},
	}

	err := p.writeConfig(ports)
	require.NoError(t, err)

	data, err := os.ReadFile(p.configPath)
	require.NoError(t, err)

	content := string(data)
	assert.Contains(t, content, `"127.0.0.1:8080": "192.168.127.2:80"`)
	assert.Contains(t, content, `"127.0.0.1:2222": "192.168.127.2:22"`)
}

func TestStop_NilCmd(t *testing.T) {
	t.Parallel()
	p := &Provider{} // cmd is nil
	// Should not panic.
	p.Stop()
}

func TestStop_NilProcess(t *testing.T) {
	t.Parallel()
	p := &Provider{
		cmd: &exec.Cmd{}, // Process is nil
	}
	p.Stop()
}

func TestSocketPath_Default(t *testing.T) {
	t.Parallel()
	p := &Provider{}
	assert.Empty(t, p.SocketPath())
}

func TestPID_Default(t *testing.T) {
	t.Parallel()
	p := &Provider{}
	assert.Equal(t, 0, p.PID())
}

func TestSocketPath_AfterSet(t *testing.T) {
	t.Parallel()
	p := &Provider{sockPath: "/tmp/test.sock"}
	assert.Equal(t, "/tmp/test.sock", p.SocketPath())
}

func TestBinaryPath_Default(t *testing.T) {
	t.Parallel()
	p := &Provider{}
	assert.Equal(t, "gvproxy", p.BinaryPath())
}

func TestBinaryPath_WithPath(t *testing.T) {
	t.Parallel()
	p := &Provider{binaryPath: "/opt/runtime/gvproxy"}
	assert.Equal(t, "/opt/runtime/gvproxy", p.BinaryPath())
}

func TestBinaryPath_CustomBinary(t *testing.T) {
	t.Parallel()
	p := &Provider{binaryPath: "/usr/local/bin/custom-net-provider"}
	assert.Equal(t, "/usr/local/bin/custom-net-provider", p.BinaryPath())
}

func TestStart_NoBinary(t *testing.T) {
	t.Parallel()
	p := &Provider{dataDir: t.TempDir()}
	err := p.Start(context.Background(), net.Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gvproxy binary not found")
}
