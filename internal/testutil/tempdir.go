// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"testing"
)

// ShortTempDir creates a temporary directory with a short path to keep
// Unix socket paths under macOS's 104-byte bind() limit. The directory
// is automatically removed when the test finishes.
//
// Use this instead of t.TempDir() when the test creates Unix sockets.
func ShortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "t")
	if err != nil {
		t.Fatalf("create short temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
