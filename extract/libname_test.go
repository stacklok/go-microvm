// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLibName(t *testing.T) {
	t.Parallel()

	got := LibName("krun", 1)

	switch runtime.GOOS {
	case "linux":
		assert.Equal(t, "libkrun.so.1", got)
	case "darwin":
		assert.Equal(t, "libkrun.1.dylib", got)
	default:
		t.Skipf("unsupported platform: %s", runtime.GOOS)
	}
}
