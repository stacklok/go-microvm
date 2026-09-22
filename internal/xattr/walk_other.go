// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package xattr

import (
	"context"
	"errors"
)

// PrepareOwnership reports that override_stat preparation is unavailable.
func PrepareOwnership(_ context.Context, _, _ string, _, _ uint32, _ bool) (PreparationReport, error) {
	return PreparationReport{}, errors.New("virtiofs ownership preparation is unsupported on this platform")
}

// SetOverrideStatTree is a no-op on platforms without xattr support.
func SetOverrideStatTree(_ string, _, _ int) error { return nil }
