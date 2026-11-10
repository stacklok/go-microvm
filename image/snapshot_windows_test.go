// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package image

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stacklok/go-microvm/internal/xattr"
)

func overrideStat(t *testing.T, path string) string {
	t.Helper()
	uid, gid, mode, ok := xattr.GetOverrideStat(path)
	require.True(t, ok, "expected override_stat metadata on %s", path)
	return fmt.Sprintf("%d:%d:0%o", uid, gid, mode)
}
