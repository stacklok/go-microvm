// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPolicy_ExactMatch(t *testing.T) {
	t.Parallel()

	p := NewPolicy([]HostSpec{
		{Name: "api.github.com"},
	})

	assert.True(t, p.IsAllowed("api.github.com"))
	assert.True(t, p.IsAllowed("API.GitHub.com"))
	assert.True(t, p.IsAllowed("api.github.com.")) // trailing dot
	assert.False(t, p.IsAllowed("github.com"))
	assert.False(t, p.IsAllowed("evil.api.github.com"))
}

func TestPolicy_WildcardMatch(t *testing.T) {
	t.Parallel()

	p := NewPolicy([]HostSpec{
		{Name: "*.docker.io"},
	})

	assert.True(t, p.IsAllowed("registry-1.docker.io"))
	assert.True(t, p.IsAllowed("auth.docker.io"))
	assert.True(t, p.IsAllowed("REGISTRY-1.Docker.IO"))
	assert.False(t, p.IsAllowed("docker.io"))
	assert.False(t, p.IsAllowed("evil.com"))
}

func TestPolicy_MultipleHosts(t *testing.T) {
	t.Parallel()

	p := NewPolicy([]HostSpec{
		{Name: "api.github.com", Ports: []uint16{443}},
		{Name: "*.docker.io"},
	})

	assert.True(t, p.IsAllowed("api.github.com"))
	assert.True(t, p.IsAllowed("registry-1.docker.io"))
	assert.False(t, p.IsAllowed("evil.com"))

	ports, _ := p.HostPorts("api.github.com")
	assert.Equal(t, []uint16{443}, ports)

	ports, _ = p.HostPorts("auth.docker.io")
	assert.Empty(t, ports) // no port restriction
}

func TestPolicy_PortsAndProtocol(t *testing.T) {
	t.Parallel()

	p := NewPolicy([]HostSpec{
		{Name: "ntp.ubuntu.com", Ports: []uint16{123}, Protocol: 17},
	})

	ports, proto := p.HostPorts("ntp.ubuntu.com")
	assert.Equal(t, []uint16{123}, ports)
	assert.Equal(t, uint8(17), proto)
}

func TestPolicy_EmptyPolicy(t *testing.T) {
	t.Parallel()

	p := NewPolicy(nil)
	assert.False(t, p.IsAllowed("anything.com"))
}

func TestPolicy_NoMatchReturnsNil(t *testing.T) {
	t.Parallel()

	p := NewPolicy([]HostSpec{
		{Name: "allowed.com"},
	})

	ports, proto := p.HostPorts("blocked.com")
	assert.Nil(t, ports)
	assert.Equal(t, uint8(0), proto)
}
