// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin

package xattr

import "os"

// SetOverrideStat is a no-op on non-darwin platforms.
func SetOverrideStat(_ string, _, _ int, _ os.FileMode) {}

// SetOverrideStatFromPath is a no-op on non-darwin platforms.
func SetOverrideStatFromPath(_ string, _, _ int) {}

// CopyOverrideStat is a no-op on non-darwin platforms.
func CopyOverrideStat(_, _ string) {}
