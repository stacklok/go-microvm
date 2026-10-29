// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package xattr

import "os"

// SetOverrideStat is a no-op on non-darwin platforms.
func SetOverrideStat(_ string, _, _ int, _ os.FileMode) error { return nil }

// SetOverrideStatFromPath is a no-op on non-darwin platforms.
func SetOverrideStatFromPath(_ string, _, _ int) error { return nil }

// CopyOverrideStat is a no-op on non-darwin platforms.
func CopyOverrideStat(_, _ string) error { return nil }
