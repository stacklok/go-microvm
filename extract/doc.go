// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package extract provides a cache-aware extraction mechanism for embedded
// binary bundles. Consumers supply file contents as byte slices; the package
// handles SHA-256 version keying, atomic directory swaps, cross-process file
// locking, and symlink creation.
package extract
