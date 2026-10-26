// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package xattr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetOverrideStat_OwnerReadOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode os.FileMode
		dir  bool
		want string
	}{
		{name: "file 0440", mode: 0o440, want: "0:0:0100440"},
		{name: "file 0400", mode: 0o400, want: "0:0:0100400"},
		{name: "setuid file 04555", mode: os.ModeSetuid | 0o555, want: "0:0:0104555"},
		{name: "directory 0555", mode: os.ModeDir | 0o555, dir: true, want: "0:0:040555"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "entry")
			if tt.dir {
				require.NoError(t, os.Mkdir(path, 0o700))
			} else {
				require.NoError(t, os.WriteFile(path, []byte("x"), 0o600))
			}
			perm := tt.mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
			//nolint:gosec // Test sets the read-only modes under test.
			require.NoError(t, os.Chmod(path, perm))
			t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

			SetOverrideStat(path, 0, 0, tt.mode)

			assert.Equal(t, tt.want, readXattr(t, path))
			info, err := os.Lstat(path)
			require.NoError(t, err)
			assert.Equal(t, perm, info.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky), "host mode restored")
		})
	}
}

func TestCopyOverrideStat_OwnerReadOnlyDestination(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	require.NoError(t, os.WriteFile(src, []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(dst, []byte("x"), 0o400))
	SetOverrideStat(src, 0, 0, 0o440)

	CopyOverrideStat(src, dst)

	assert.Equal(t, "0:0:0100440", readXattr(t, dst))
	info, err := os.Lstat(dst)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o400), info.Mode().Perm())
}
