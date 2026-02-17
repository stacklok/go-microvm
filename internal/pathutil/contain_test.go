// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package pathutil

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestContains(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		root    string
		rel     string
		want    string
		wantErr string
	}{
		{
			name: "simple relative path",
			root: "/rootfs",
			rel:  "etc/passwd",
			want: "/rootfs/etc/passwd",
		},
		{
			name: "absolute guest path (leading slash stripped)",
			root: "/rootfs",
			rel:  "/etc/passwd",
			want: "/rootfs/etc/passwd",
		},
		{
			name: "nested path",
			root: "/rootfs",
			rel:  "home/sandbox/.ssh/authorized_keys",
			want: "/rootfs/home/sandbox/.ssh/authorized_keys",
		},
		{
			name:    "dot-dot escape",
			root:    "/rootfs",
			rel:     "../../etc/shadow",
			wantErr: "path traversal",
		},
		{
			name: "absolute with dot-dot collapses to root",
			root: "/rootfs",
			rel:  "/../../../etc/shadow",
			want: "/rootfs/etc/shadow", // filepath.Clean absorbs ../ above /
		},
		{
			name:    "embedded dot-dot",
			root:    "/rootfs",
			rel:     "foo/../../etc/shadow",
			wantErr: "path traversal",
		},
		{
			name: "dot in path is safe",
			root: "/rootfs",
			rel:  "./etc/config",
			want: "/rootfs/etc/config",
		},
		{
			name: "single dot",
			root: "/rootfs",
			rel:  ".",
			want: "/rootfs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Contains(tt.root, tt.rel)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, filepath.Clean(tt.want), got)
		})
	}
}
