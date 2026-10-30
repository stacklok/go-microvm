// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileMode(t *testing.T) {
	t.Parallel()

	special := os.FileMode(0)
	if KeepsSpecialBits() {
		special = os.ModeSetuid | os.ModeSetgid
	}
	assert.Equal(t, os.FileMode(0o644), FileMode(0o644))
	assert.Equal(t, os.FileMode(0o755), FileMode(os.ModeSticky|0o755))
	assert.Equal(t, special|0o755, FileMode(os.ModeSetuid|os.ModeSetgid|0o755))
}

func TestRestoreSpecialBits(t *testing.T) {
	t.Parallel()

	const special = os.ModeSetuid | os.ModeSetgid
	tests := []struct {
		name string
		mode os.FileMode
	}{
		{name: "setuid", mode: os.ModeSetuid | 0o755},
		{name: "setgid", mode: os.ModeSetgid | 0o755},
		{name: "both", mode: special | 0o755},
		{name: "none", mode: 0o755},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The file starts without the bits, as after a chown.
			path := filepath.Join(t.TempDir(), "file")
			require.NoError(t, os.WriteFile(path, nil, 0o755)) //nolint:gosec // executable test file
			info, err := os.Stat(path)
			require.NoError(t, err)

			want := tt.mode & os.ModeSetuid
			if tt.mode&os.ModeSetgid != 0 && inGroup(int(info.Sys().(*syscall.Stat_t).Gid)) {
				want |= os.ModeSetgid
			}

			require.NoError(t, RestoreSpecialBits(path, tt.mode))
			info, err = os.Stat(path)
			require.NoError(t, err)
			assert.Equal(t, want|0o755, info.Mode()&(special|os.ModePerm))
		})
	}

	t.Run("directory", func(t *testing.T) {
		t.Parallel()

		dir := t.TempDir()
		require.NoError(t, os.Chmod(dir, 0o755))
		require.NoError(t, RestoreSpecialBits(dir, special|0o755))
		info, err := os.Stat(dir)
		require.NoError(t, err)
		assert.Zero(t, info.Mode()&special)
	})
}
