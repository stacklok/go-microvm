// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package pathutil

import "os"

// RestoreSpecialBits is a no-op because Windows does not retain Unix set-id bits.
func RestoreSpecialBits(_ string, _ os.FileMode) error {
	return nil
}
