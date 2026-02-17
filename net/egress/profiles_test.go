// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermissive_ReturnsNil(t *testing.T) {
	t.Parallel()

	result := Permissive()
	assert.Nil(t, result)
}

func TestStandard_ContainsExpectedHosts(t *testing.T) {
	t.Parallel()

	hosts := Standard()
	names := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		names[h.Name] = struct{}{}
	}

	tests := []struct {
		name     string
		expected string
	}{
		{name: "GitHub wildcard", expected: "*.github.com"},
		{name: "GitHub exact", expected: "github.com"},
		{name: "npm wildcard", expected: "*.npmjs.org"},
		{name: "npm registry", expected: "registry.npmjs.org"},
		{name: "PyPI wildcard", expected: "*.pypi.org"},
		{name: "PyPI exact", expected: "pypi.org"},
		{name: "Python hosted", expected: "files.pythonhosted.org"},
		{name: "Go proxy", expected: "proxy.golang.org"},
		{name: "Go sum", expected: "sum.golang.org"},
		{name: "Docker wildcard", expected: "*.docker.io"},
		{name: "Docker exact", expected: "docker.io"},
		{name: "Docker.com wildcard", expected: "*.docker.com"},
		{name: "Crates.io", expected: "crates.io"},
		{name: "Crates.io wildcard", expected: "*.crates.io"},
		{name: "Crates.io static", expected: "static.crates.io"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, ok := names[tt.expected]
			assert.True(t, ok, "expected host %q not found in Standard()", tt.expected)
		})
	}
}

func TestStandard_AcceptsAdditional(t *testing.T) {
	t.Parallel()

	additional := HostSpec{Name: "custom.example.com"}
	hosts := Standard(additional)

	found := false
	for _, h := range hosts {
		if h.Name == "custom.example.com" {
			found = true
			break
		}
	}
	require.True(t, found, "additional host not found in result")
}

func TestStandard_NoDuplicates(t *testing.T) {
	t.Parallel()

	// Add a host that already exists in the base set.
	duplicate := HostSpec{Name: "github.com"}
	hosts := Standard(duplicate)

	count := 0
	for _, h := range hosts {
		if h.Name == "github.com" {
			count++
		}
	}
	assert.Equal(t, 1, count, "github.com should appear exactly once")
}

func TestLocked_ReturnsOnlyProvided(t *testing.T) {
	t.Parallel()

	input := []HostSpec{
		{Name: "api.example.com"},
		{Name: "cdn.example.com", Ports: []uint16{443}},
	}
	result := Locked(input...)

	require.Len(t, result, 2)
	assert.Equal(t, "api.example.com", result[0].Name)
	assert.Equal(t, "cdn.example.com", result[1].Name)
	assert.Equal(t, []uint16{443}, result[1].Ports)
}
