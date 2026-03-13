// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package harden provides guest-side kernel, capability, and syscall
// hardening for microVM init processes. It restricts kernel information
// leaks, limits unprivileged access to dangerous subsystems, drops
// unneeded capabilities from the bounding set, and installs a seccomp
// BPF filter that blocks dangerous syscalls.
//
// Consumers should call [KernelDefaults] early in the boot sequence
// (after /proc is mounted), [DropBoundingCaps] after all privileged
// operations are complete, and [ApplySeccomp] as the very last
// hardening step — after mounts, networking, and SSH are ready.
package harden
