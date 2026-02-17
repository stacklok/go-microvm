// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package env

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string // file content; empty string means write empty file
		missing bool   // if true, don't create the file at all
		want    []string
		wantErr bool
	}{
		{
			name:    "simple value",
			content: "export FOO='bar'\n",
			want:    []string{"FOO=bar"},
		},
		{
			name:    "value with spaces",
			content: "export MSG='hello world'\n",
			want:    []string{"MSG=hello world"},
		},
		{
			name:    "value with escaped single quotes",
			content: "export Q='it'\\''s here'\n",
			want:    []string{"Q=it's here"},
		},
		{
			name: "multiple variables",
			content: "export A='one'\n" +
				"export B='two'\n" +
				"export C='three'\n",
			want: []string{"A=one", "B=two", "C=three"},
		},
		{
			name:    "empty file",
			content: "",
			want:    nil,
		},
		{
			name:    "missing file returns nil without error",
			missing: true,
			want:    nil,
		},
		{
			name:    "comment lines are skipped",
			content: "# this is a comment\nexport REAL='value'\n# another comment\n",
			want:    []string{"REAL=value"},
		},
		{
			name:    "lines without export prefix are skipped",
			content: "FOO='bar'\nexport GOOD='yes'\nBAD='no'\n",
			want:    []string{"GOOD=yes"},
		},
		{
			name:    "empty value",
			content: "export EMPTY=''\n",
			want:    []string{"EMPTY="},
		},
		{
			name:    "only comments",
			content: "# comment 1\n# comment 2\n",
			want:    nil,
		},
		{
			name:    "value with binary-like content",
			content: "export BIN='\\x00\\xff'\n",
			want:    []string{"BIN=\\x00\\xff"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "sandbox-env")

			if !tt.missing {
				err := os.WriteFile(path, []byte(tt.content), 0o644)
				require.NoError(t, err)
			}

			got, err := Load(path)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUnquote(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "simple single-quoted string",
			input: "'hello'",
			want:  "hello",
		},
		{
			name:  "escaped single quote",
			input: "'it'\\''s here'",
			want:  "it's here",
		},
		{
			name:  "no quotes returns as-is",
			input: "bare",
			want:  "bare",
		},
		{
			name:  "empty quoted string",
			input: "''",
			want:  "",
		},
		{
			name:  "multiple escaped quotes",
			input: "'don'\\''t say '\\''no'\\'''",
			want:  "don't say 'no'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, Unquote(tt.input))
		})
	}
}

func TestLoad_MaxFileSize(t *testing.T) {
	t.Parallel()

	// Create a file larger than maxFileSize with valid content at the start.
	dir := t.TempDir()
	path := filepath.Join(dir, "sandbox-env")

	var sb strings.Builder
	sb.WriteString("export FIRST='value'\n")
	// Pad with enough data to exceed 1 MB.
	for sb.Len() < maxFileSize+100 {
		sb.WriteString("export PAD='x'\n")
	}
	err := os.WriteFile(path, []byte(sb.String()), 0o644)
	require.NoError(t, err)

	// Should still parse successfully (truncated by LimitReader).
	got, err := Load(path)
	require.NoError(t, err)
	assert.Contains(t, got, "FIRST=value")
}
