// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !linux

package vhd

func getOverrideStat(_ string) (int, int, int64, bool) {
	return 0, 0, 0, false
}
