// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package extract

import "fmt"

// libName returns the versioned macOS dylib filename, e.g. "libkrun.1.dylib".
// macOS dylib install names include the major version before the .dylib suffix,
// so the extracted filename must match what the binary was linked against.
func libName(base string, major int) string {
	return fmt.Sprintf("lib%s.%d.dylib", base, major)
}
