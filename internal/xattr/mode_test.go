// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package xattr

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGoFileModeToPosix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode os.FileMode
		want uint32
	}{
		{"regular 644", 0o644, 0o100644},
		{"regular 755", 0o755, 0o100755},
		{"regular 600", 0o600, 0o100600},
		{"dir 755", os.ModeDir | 0o755, 0o040755},
		{"dir 700", os.ModeDir | 0o700, 0o040700},
		{"symlink", os.ModeSymlink | 0o777, 0o120777},
		{"setuid", os.ModeSetuid | 0o755, 0o104755},
		{"setgid", os.ModeSetgid | 0o755, 0o102755},
		{"sticky", os.ModeSticky | 0o755, 0o101755},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := goFileModeToPosix(tt.mode)
			assert.Equal(t, tt.want, got)
		})
	}
}
