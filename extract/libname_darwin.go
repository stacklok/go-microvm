// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package extract

import "fmt"

func libName(base string, major int) string {
	return fmt.Sprintf("lib%s.%d.dylib", base, major)
}
