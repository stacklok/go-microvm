// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package hooks provides reusable RootFSHook builders for injecting files,
// binaries, SSH keys, and environment files into guest rootfs directories
// before VM boot.
//
// Functions return func(string, *image.OCIConfig) error which is structurally
// identical to microvm.RootFSHook.
package hooks
