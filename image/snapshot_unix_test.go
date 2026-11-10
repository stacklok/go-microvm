// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package image

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func overrideStat(t *testing.T, path string) string {
	t.Helper()
	buf := make([]byte, 256)
	n, err := unix.Lgetxattr(path, "user.containers.override_stat", buf)
	require.NoError(t, err)
	return string(buf[:n])
}
