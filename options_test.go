// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package propolis

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/propolis/image"
	"github.com/stacklok/propolis/net/firewall"
	"github.com/stacklok/propolis/preflight"
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

func TestWithDataDir(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	WithDataDir("/custom/data").apply(cfg)

	assert.Equal(t, "/custom/data", cfg.dataDir)
	assert.NotNil(t, cfg.imageCache) // imageCache should be recreated
}

func TestWithCleanDataDir(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.False(t, cfg.cleanDataDir)

	WithCleanDataDir().apply(cfg)
	assert.True(t, cfg.cleanDataDir)
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

func TestWithFirewallRules(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Empty(t, cfg.firewallRules)

	rules := []firewall.Rule{
		{Direction: firewall.Egress, Action: firewall.Allow, DstPort: 443, Comment: "allow HTTPS"},
		{Direction: firewall.Egress, Action: firewall.Deny, Comment: "deny all other egress"},
	}
	WithFirewallRules(rules...).apply(cfg)

	require.Len(t, cfg.firewallRules, 2)
	assert.Equal(t, uint16(443), cfg.firewallRules[0].DstPort)
	assert.Equal(t, firewall.Allow, cfg.firewallRules[0].Action)
	assert.Equal(t, "allow HTTPS", cfg.firewallRules[0].Comment)
	assert.Equal(t, firewall.Deny, cfg.firewallRules[1].Action)
}

func TestWithFirewallDefaultAction(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Equal(t, firewall.Allow, cfg.firewallDefaultAction)

	WithFirewallDefaultAction(firewall.Deny).apply(cfg)
	assert.Equal(t, firewall.Deny, cfg.firewallDefaultAction)
}

func TestWithEgressPolicy(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Nil(t, cfg.egressPolicy)

	policy := EgressPolicy{
		AllowedHosts: []EgressHost{
			{Name: "api.github.com", Ports: []uint16{443}, Protocol: 6},
		},
	}
	WithEgressPolicy(policy).apply(cfg)

	require.NotNil(t, cfg.egressPolicy)
	require.Len(t, cfg.egressPolicy.AllowedHosts, 1)
	assert.Equal(t, "api.github.com", cfg.egressPolicy.AllowedHosts[0].Name)
	assert.Equal(t, []uint16{443}, cfg.egressPolicy.AllowedHosts[0].Ports)
	assert.Equal(t, uint8(6), cfg.egressPolicy.AllowedHosts[0].Protocol)
}

func TestWithPreflightChecks(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	cfg.preflight = preflight.NewEmpty()

	ran := false
	check := preflight.Check{
		Name:        "test-check",
		Description: "a test check",
		Required:    true,
		Run: func(_ context.Context) error {
			ran = true
			return nil
		},
	}
	WithPreflightChecks(check).apply(cfg)

	// Verify the check was registered by running all checks.
	err := cfg.preflight.RunAll(context.Background())
	require.NoError(t, err)
	assert.True(t, ran)
}

func TestWithImageCache(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	originalCache := cfg.imageCache

	newCache := image.NewCache(t.TempDir())
	WithImageCache(newCache).apply(cfg)

	assert.NotEqual(t, originalCache, cfg.imageCache)
	assert.Equal(t, newCache, cfg.imageCache)
}
