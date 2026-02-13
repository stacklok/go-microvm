// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	require.NotNil(t, cfg)

	assert.Equal(t, uint32(1), cfg.cpus)
	assert.Equal(t, uint32(512), cfg.memory)
	assert.Equal(t, "propolis", cfg.name)
	assert.NotNil(t, cfg.preflight)
	assert.Nil(t, cfg.netProvider) // lazy-initialized in Run() when not set by WithNetProvider
	assert.NotNil(t, cfg.imageCache)
	assert.Nil(t, cfg.ports)
}

func TestWithCPUs(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithCPUs(8).apply(cfg)

	assert.Equal(t, uint32(8), cfg.cpus)
}

func TestWithMemory(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithMemory(2048).apply(cfg)

	assert.Equal(t, uint32(2048), cfg.memory)
}

func TestWithPorts_Appends(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()

	WithPorts(PortForward{Host: 8080, Guest: 80}).apply(cfg)
	WithPorts(PortForward{Host: 8443, Guest: 443}).apply(cfg)

	require.Len(t, cfg.ports, 2)
	assert.Equal(t, uint16(8080), cfg.ports[0].Host)
	assert.Equal(t, uint16(80), cfg.ports[0].Guest)
	assert.Equal(t, uint16(8443), cfg.ports[1].Host)
	assert.Equal(t, uint16(443), cfg.ports[1].Guest)
}

func TestWithPorts_MultipleInSingleCall(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()

	WithPorts(
		PortForward{Host: 8080, Guest: 80},
		PortForward{Host: 8443, Guest: 443},
	).apply(cfg)

	require.Len(t, cfg.ports, 2)
}

func TestWithInitOverride(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithInitOverride("/custom/init", "--flag").apply(cfg)

	assert.Equal(t, []string{"/custom/init", "--flag"}, cfg.initOverride)
}

func TestWithName(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithName("my-vm").apply(cfg)

	assert.Equal(t, "my-vm", cfg.name)
}

func TestWithLibDir(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithLibDir("/usr/local/lib/krun").apply(cfg)

	assert.Equal(t, "/usr/local/lib/krun", cfg.libDir)
}

func TestWithRunnerPath(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithRunnerPath("/usr/bin/propolis-runner").apply(cfg)

	assert.Equal(t, "/usr/bin/propolis-runner", cfg.runnerPath)
}

func TestWithDataDir(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithDataDir("/custom/data").apply(cfg)

	assert.Equal(t, "/custom/data", cfg.dataDir)
	assert.NotNil(t, cfg.imageCache) // imageCache should be recreated
}

func TestWithRootFSPath(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Empty(t, cfg.rootfsPath)

	WithRootFSPath("/path/to/rootfs").apply(cfg)
	assert.Equal(t, "/path/to/rootfs", cfg.rootfsPath)
}

func TestWithRootFSPath_OverridesDefault(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithRootFSPath("/first").apply(cfg)
	WithRootFSPath("/second").apply(cfg)

	assert.Equal(t, "/second", cfg.rootfsPath)
}

func TestWithVirtioFS(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithVirtioFS(
		VirtioFSMount{Tag: "workspace", HostPath: "/home/user/src"},
	).apply(cfg)

	require.Len(t, cfg.virtioFS, 1)
	assert.Equal(t, "workspace", cfg.virtioFS[0].Tag)
	assert.Equal(t, "/home/user/src", cfg.virtioFS[0].HostPath)
}

func TestWithVirtioFS_Appends(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithVirtioFS(VirtioFSMount{Tag: "first", HostPath: "/a"}).apply(cfg)
	WithVirtioFS(VirtioFSMount{Tag: "second", HostPath: "/b"}).apply(cfg)

	require.Len(t, cfg.virtioFS, 2)
	assert.Equal(t, "first", cfg.virtioFS[0].Tag)
	assert.Equal(t, "second", cfg.virtioFS[1].Tag)
}

func TestWithNetProviderBinaryPath(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Empty(t, cfg.netProviderBinaryPath)

	WithNetProviderBinaryPath("/opt/bin/gvproxy").apply(cfg)
	assert.Equal(t, "/opt/bin/gvproxy", cfg.netProviderBinaryPath)
}

func TestMultipleOptionsApplied(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()

	opts := []Option{
		WithName("test-vm"),
		WithCPUs(4),
		WithMemory(1024),
		WithPorts(PortForward{Host: 2222, Guest: 22}),
		WithInitOverride("/sbin/custom-init"),
	}

	for _, opt := range opts {
		opt.apply(cfg)
	}

	assert.Equal(t, "test-vm", cfg.name)
	assert.Equal(t, uint32(4), cfg.cpus)
	assert.Equal(t, uint32(1024), cfg.memory)
	require.Len(t, cfg.ports, 1)
	assert.Equal(t, uint16(2222), cfg.ports[0].Host)
	assert.Equal(t, []string{"/sbin/custom-init"}, cfg.initOverride)
}
