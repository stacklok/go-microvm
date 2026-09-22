// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package virtiofs prepares host files for libkrun virtio-fs ownership mapping.
//
// PrepareOwnership changes only the user.containers.override_stat extended
// attribute. It does not change host ownership or permissions.
package virtiofs
