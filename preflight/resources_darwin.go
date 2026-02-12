// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package preflight

import (
	"context"
	"fmt"
)

// DiskSpaceCheck returns a no-op Check on macOS. Resource checking on macOS
// requires different system calls and is not yet implemented.
func DiskSpaceCheck(_ string, minFreeGB float64) Check {
	return Check{
		Name:        "disk-space",
		Description: fmt.Sprintf("Verify at least %.1f GB free disk space", minFreeGB),
		Run:         func(_ context.Context) error { return nil },
		Required:    false,
	}
}

// ResourceCheck returns a no-op Check on macOS. Resource checking on macOS
// requires different system calls and is not yet implemented.
func ResourceCheck(minCPUs int, minMemoryGiB float64) Check {
	return Check{
		Name:        "resources",
		Description: fmt.Sprintf("Verify minimum resources (%d CPUs, %.1f GiB RAM)", minCPUs, minMemoryGiB),
		Run:         func(_ context.Context) error { return nil },
		Required:    false,
	}
}
