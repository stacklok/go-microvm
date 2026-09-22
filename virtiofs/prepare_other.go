// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package virtiofs

import (
	"context"
	"fmt"
	"runtime"
)

// PrepareOwnership reports that override_stat preparation is unavailable.
func PrepareOwnership(_ context.Context, _, _ string, _, _ uint32) error {
	return fmt.Errorf("virtiofs ownership preparation is unsupported on %s", runtime.GOOS)
}
