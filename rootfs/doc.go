// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package rootfs provides copy-on-write directory cloning for rootfs isolation.
//
// When an OCI image is served from cache, hooks must not modify the cached
// copy. CloneDir creates a working copy using platform-native COW primitives
// (FICLONE on Linux, clonefile on macOS) with a regular-copy fallback, so
// hooks operate on an isolated directory while the cache stays pristine.
package rootfs
