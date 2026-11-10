// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package extract

import "fmt"

func libName(base string, major int) string {
	if major <= 0 {
		return fmt.Sprintf("%s.dll", base)
	}
	return fmt.Sprintf("%s-%d.dll", base, major)
}
