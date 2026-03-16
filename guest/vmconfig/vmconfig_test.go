// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package vmconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content *string // nil = file does not exist
		want    Config
		wantErr bool
	}{
		{
			name:    "file does not exist",
			content: nil,
			want:    Config{},
		},
		{
			name:    "valid JSON with TmpSizeMiB",
			content: strPtr(`{"tmp_size_mib":512}`),
			want:    Config{TmpSizeMiB: 512},
		},
		{
			name:    "empty JSON object",
			content: strPtr(`{}`),
			want:    Config{},
		},
		{
			name:    "malformed JSON",
			content: strPtr(`{not json`),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "vm.json")

			if tt.content != nil {
				require.NoError(t, os.WriteFile(path, []byte(*tt.content), 0o644))
			}

			got, err := ReadFromForTest(path)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func strPtr(s string) *string { return &s }
