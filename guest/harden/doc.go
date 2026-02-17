// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package harden provides guest-side kernel and capability hardening for
// microVM init processes. It restricts kernel information leaks, limits
// unprivileged access to dangerous subsystems, and drops unneeded
// capabilities from the bounding set.
//
// Consumers (e.g. apiary-init) should call [KernelDefaults] early in the
// boot sequence (after /proc is mounted) and [DropBoundingCaps] last,
// just before starting the workload, so that all privileged operations
// (mounts, network config, chown) are already complete.
package harden
