// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package runner

import (
	"path/filepath"

	"github.com/stacklok/go-microvm/internal/procutil"
)

func isExpectedProcess(pid int, expectedPath string) bool {
	return procutil.IsExpectedProcess(pid, filepath.Base(expectedPath))
}
