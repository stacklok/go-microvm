// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package extract

func libName(base string, _ int) string {
	return "lib" + base + ".dylib"
}
