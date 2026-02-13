// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runner

import "github.com/stacklok/propolis/internal/procutil"

// isExpectedProcess checks if the process at pid is running the expected binary.
// Delegates to the shared implementation in internal/procutil.
func isExpectedProcess(pid int, expectedBinary string) bool {
	return procutil.IsExpectedProcess(pid, expectedBinary)
}
