// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package preflight

import "context"

// UserNamespaceCheck returns a no-op preflight check on non-Linux platforms.
// User namespaces are a Linux-specific feature.
func UserNamespaceCheck() Check {
	return Check{
		Name:        "userns",
		Description: "Verify unprivileged user namespaces are available (Linux only)",
		Run:         func(_ context.Context) error { return nil },
		Required:    false,
	}
}
