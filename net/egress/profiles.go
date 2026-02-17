// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

// Permissive returns nil, indicating no egress restrictions.
func Permissive() []HostSpec { return nil }

// Standard returns a curated set of common development hosts.
// Additional hosts are appended without duplicating existing entries.
func Standard(additional ...HostSpec) []HostSpec {
	base := []HostSpec{
		{Name: "*.github.com"},
		{Name: "github.com"},
		{Name: "*.githubusercontent.com"},
		{Name: "*.npmjs.org"},
		{Name: "registry.npmjs.org"},
		{Name: "*.pypi.org"},
		{Name: "pypi.org"},
		{Name: "files.pythonhosted.org"},
		{Name: "proxy.golang.org"},
		{Name: "sum.golang.org"},
		{Name: "*.docker.io"},
		{Name: "docker.io"},
		{Name: "*.docker.com"},
		{Name: "crates.io"},
		{Name: "*.crates.io"},
		{Name: "static.crates.io"},
	}
	// Deduplicate additional hosts.
	seen := make(map[string]struct{}, len(base))
	for _, h := range base {
		seen[h.Name] = struct{}{}
	}
	for _, h := range additional {
		if _, ok := seen[h.Name]; ok {
			continue
		}
		seen[h.Name] = struct{}{}
		base = append(base, h)
	}
	return base
}

// Locked returns only the specified hosts with no defaults.
func Locked(hosts ...HostSpec) []HostSpec { return hosts }
