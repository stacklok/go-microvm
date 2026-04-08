// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package xattr

// SetOverrideStatTree is a no-op on platforms without xattr support.
func SetOverrideStatTree(_ string, _, _ int) error { return nil }
