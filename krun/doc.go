// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package krun provides CGO bindings to libkrun for lightweight microVM management.
//
// libkrun is a library that allows running lightweight virtual machines using
// KVM on Linux and Hypervisor.framework on macOS. This package wraps the C API
// with safe Go types and error handling.
//
// The bindings are only available when CGO is enabled on Linux or macOS.
// Use [IsAvailable] to check at runtime whether libkrun is functional.
//
// The primary consumer of this package is the go-microvm-runner binary
// (runner/cmd/go-microvm-runner), which is spawned as a subprocess to run VMs.
// The main go-microvm library does not link against libkrun directly; it
// communicates with libkrun through the runner subprocess.
package krun
