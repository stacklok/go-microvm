// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package xattr sets libkrun's user.containers.override_stat extended
// attribute on macOS and Linux so that the virtiofs server reports correct
// guest-visible ownership and permissions for rootfs files.
//
// When go-microvm extracts an OCI image, the host user ends up owning all
// files because non-root cannot chown. libkrun's virtiofs server
// performs access checks against these host-side attributes, causing
// permission denied errors for guest processes running as UIDs that
// don't exist on the host (e.g. uid 1000).
//
// Setting this xattr on each file tells the virtiofs server to override
// the reported stat values, making the guest see the correct ownership
// from the original OCI image. This is the same mechanism that podman
// uses on macOS.
//
// On Linux, the kernel restricts user.* xattrs to regular files and
// directories — symlinks and special files are silently skipped. This
// is acceptable because applications check the target's ownership, not
// the symlink itself.
//
// On platforms other than macOS and Linux these functions are no-ops.
package xattr
