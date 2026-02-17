// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package harden

// Test-only exports for verifying internal logic without root privileges.
var (
	ParseCapLastCapForTest = parseCapLastCap
	KeepSetContainsForTest = keepSetContains
	SysctlPathForTest      = sysctlPath
	DefaultsForTest        = defaults
)
