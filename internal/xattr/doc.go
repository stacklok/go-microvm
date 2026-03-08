// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package xattr sets libkrun's user.containers.override_stat extended
// attribute on macOS so that the virtiofs FUSE server reports correct
// guest-visible ownership and permissions for rootfs files.
//
// When propolis extracts an OCI image on macOS, the host user (typically
// uid 501) ends up owning all files because non-root cannot chown.
// libkrun's FUSE server performs access checks against these host-side
// attributes, causing permission denied errors for guest processes
// running as UIDs that don't exist on the host (e.g. uid 1000).
//
// Setting this xattr on each file tells the FUSE server to override
// the reported stat values, making the guest see the correct ownership
// from the original OCI image. This is the same mechanism that podman
// uses on macOS.
//
// On non-darwin platforms these functions are no-ops.
package xattr
