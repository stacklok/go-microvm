// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package gvproxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew_SetsDataDir(t *testing.T) {
	t.Parallel()

	p := New("/tmp/test-data")
	assert.Equal(t, "/tmp/test-data", p.dataDir)
}

func TestNewWithBinaryPath_SetsFields(t *testing.T) {
	t.Parallel()

	p := NewWithBinaryPath("/usr/local/bin/gvproxy", "/tmp/test-data")

	assert.Equal(t, "/usr/local/bin/gvproxy", p.binaryPath)
	assert.Equal(t, "/tmp/test-data", p.dataDir)
}

func TestNewWithBinaryPath_SkipsLookPath(t *testing.T) {
	t.Parallel()

	// NewWithBinaryPath should use the path as-is, even if the binary
	// doesn't actually exist at that path.
	p := NewWithBinaryPath("/nonexistent/gvproxy", "/tmp/data")

	assert.Equal(t, "/nonexistent/gvproxy", p.binaryPath)
}
