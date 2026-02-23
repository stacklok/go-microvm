// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package version

// Build-time variables injected via ldflags.
var (
	// Version is the release version (e.g. "v0.2.0" or "dev").
	Version = "dev"

	// Commit is the short git commit hash.
	Commit = "unknown"

	// BuildDate is the UTC build timestamp in RFC 3339 format.
	BuildDate = "unknown"
)
