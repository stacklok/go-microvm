// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package version holds build-time version information injected via ldflags.
// The variables in this package are set by the linker during build:
//
//	go build -ldflags "-X github.com/stacklok/go-microvm/internal/version.Version=..."
package version
