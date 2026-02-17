// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package extract

// LibName returns the platform-specific shared library filename for the
// given base name and major version number.
func LibName(base string, major int) string {
	return libName(base, major)
}
