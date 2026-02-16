// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package egress

import "strings"

// Policy holds an allowlist of hostnames that the VM is permitted to
// connect to. Matching supports exact names and wildcard prefixes.
type Policy struct {
	hosts []hostEntry
}

type hostEntry struct {
	wildcard bool
	suffix   string // for wildcards: ".docker.io"
	exact    string // for exact: "api.github.com"
	ports    []uint16
	protocol uint8
}

// HostSpec describes a single allowed hostname with optional port/protocol
// restrictions. This is the input type for NewPolicy.
type HostSpec struct {
	Name     string   // "api.github.com" or "*.docker.io"
	Ports    []uint16 // empty = all ports
	Protocol uint8    // 0 = both TCP+UDP, 6 = TCP only, 17 = UDP only
}

// NewPolicy creates a policy from the given host specifications.
//
// Name matching rules:
//   - Exact: "api.github.com" matches "api.github.com" only
//   - Wildcard: "*.docker.io" matches "registry-1.docker.io",
//     "auth.docker.io", but NOT "docker.io" itself
func NewPolicy(hosts []HostSpec) *Policy {
	entries := make([]hostEntry, len(hosts))
	for i, h := range hosts {
		name := strings.ToLower(strings.TrimSuffix(h.Name, "."))
		e := hostEntry{
			ports:    h.Ports,
			protocol: h.Protocol,
		}
		if strings.HasPrefix(name, "*.") {
			e.wildcard = true
			e.suffix = name[1:] // ".docker.io"
		} else {
			e.exact = name
		}
		entries[i] = e
	}
	return &Policy{hosts: entries}
}

// IsAllowed reports whether the given hostname matches any entry in the policy.
func (p *Policy) IsAllowed(name string) bool {
	_, ok := p.matchHost(name)
	return ok
}

// HostPorts returns the port restrictions and protocol for a matched host.
// If no match is found, it returns nil, 0.
func (p *Policy) HostPorts(name string) ([]uint16, uint8) {
	e, ok := p.matchHost(name)
	if !ok {
		return nil, 0
	}
	return e.ports, e.protocol
}

func (p *Policy) matchHost(name string) (hostEntry, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, e := range p.hosts {
		if e.wildcard {
			if strings.HasSuffix(name, e.suffix) && len(name) > len(e.suffix) {
				return e, true
			}
		} else {
			if name == e.exact {
				return e, true
			}
		}
	}
	return hostEntry{}, false
}
