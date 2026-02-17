// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hooks

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInjectFile_WritesContent(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	content := []byte("hello world")
	hook := InjectFile("/etc/myconfig.txt", content, 0o644)

	err := hook(rootfs, nil)
	require.NoError(t, err)

	got, err := os.ReadFile(filepath.Join(rootfs, "etc", "myconfig.txt"))
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestInjectFile_CreatesParentDirs(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	hook := InjectFile("/deep/nested/dir/file.txt", []byte("data"), 0o644)

	err := hook(rootfs, nil)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(rootfs, "deep", "nested", "dir"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	got, err := os.ReadFile(filepath.Join(rootfs, "deep", "nested", "dir", "file.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("data"), got)
}

func TestInjectBinary_Permissions(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	hook := InjectBinary("/usr/bin/mytool", []byte("#!/bin/sh\necho hi"))

	err := hook(rootfs, nil)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(rootfs, "usr", "bin", "mytool"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o755), info.Mode().Perm())
}

func TestInjectEnvFile_ShellEscaping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		envMap   map[string]string
		expected string
	}{
		{
			name:     "simple value",
			envMap:   map[string]string{"KEY": "value"},
			expected: "export KEY='value'\n",
		},
		{
			name:     "value with single quotes",
			envMap:   map[string]string{"KEY": "it's here"},
			expected: "export KEY='it'\\''s here'\n",
		},
		{
			name:     "value with newlines",
			envMap:   map[string]string{"KEY": "line1\nline2"},
			expected: "export KEY='line1\nline2'\n",
		},
		{
			name:     "value with backslashes",
			envMap:   map[string]string{"KEY": "path\\to\\file"},
			expected: "export KEY='path\\to\\file'\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rootfs := t.TempDir()
			hook := InjectEnvFile("/etc/env", tt.envMap)

			err := hook(rootfs, nil)
			require.NoError(t, err)

			got, err := os.ReadFile(filepath.Join(rootfs, "etc", "env"))
			require.NoError(t, err)
			assert.Equal(t, tt.expected, string(got))
		})
	}
}

func TestInjectEnvFile_Permissions(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	hook := InjectEnvFile("/etc/env", map[string]string{"SECRET": "password"})

	err := hook(rootfs, nil)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(rootfs, "etc", "env"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestInjectEnvFile_EmptyMap(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	hook := InjectEnvFile("/etc/env", map[string]string{})

	err := hook(rootfs, nil)
	require.NoError(t, err)

	// File should not be created for empty map.
	_, err = os.Stat(filepath.Join(rootfs, "etc", "env"))
	assert.True(t, os.IsNotExist(err))
}

func TestInjectAuthorizedKeys_DefaultPaths(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	// Pre-create the home directory so chown doesn't fail.
	require.NoError(t, os.MkdirAll(filepath.Join(rootfs, "home", "sandbox"), 0o755))

	pubKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAATEST test@example.com"
	hook := InjectAuthorizedKeys(pubKey)

	err := hook(rootfs, nil)
	require.NoError(t, err)

	// Verify .ssh directory exists.
	sshDir := filepath.Join(rootfs, "home", "sandbox", ".ssh")
	info, err := os.Stat(sshDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())

	// Verify authorized_keys content.
	akPath := filepath.Join(sshDir, "authorized_keys")
	got, err := os.ReadFile(akPath)
	require.NoError(t, err)
	assert.Equal(t, pubKey+"\n", string(got))

	// Verify authorized_keys permissions.
	info, err = os.Stat(akPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestInjectAuthorizedKeys_CustomUser(t *testing.T) {
	t.Parallel()

	// Use current user's UID/GID to avoid permission errors in tests.
	u, err := user.Current()
	require.NoError(t, err)
	uid, err := strconv.Atoi(u.Uid)
	require.NoError(t, err)
	gid, err := strconv.Atoi(u.Gid)
	require.NoError(t, err)

	rootfs := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(rootfs, "customhome"), 0o755))

	pubKey := "ssh-rsa AAAAB3NzaC1yc2EAAAADTEST custom@host"
	hook := InjectAuthorizedKeys(pubKey, WithKeyUser("/customhome", uid, gid))

	err = hook(rootfs, nil)
	require.NoError(t, err)

	// Verify custom path.
	akPath := filepath.Join(rootfs, "customhome", ".ssh", "authorized_keys")
	got, err := os.ReadFile(akPath)
	require.NoError(t, err)
	assert.Equal(t, pubKey+"\n", string(got))

	// Verify .ssh directory permissions.
	info, err := os.Stat(filepath.Join(rootfs, "customhome", ".ssh"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
}

func TestInjectFile_RejectsPathTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		guestPath string
	}{
		{"dot-dot", "../../etc/shadow"},
		{"embedded dot-dot", "foo/../../etc/shadow"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rootfs := t.TempDir()
			hook := InjectFile(tt.guestPath, []byte("evil"), 0o644)
			err := hook(rootfs, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "path traversal")
		})
	}
}

func TestInjectBinary_RejectsPathTraversal(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	hook := InjectBinary("../../usr/bin/evil", []byte("payload"))
	err := hook(rootfs, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")
}

func TestInjectEnvFile_RejectsPathTraversal(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	hook := InjectEnvFile("../../etc/env", map[string]string{"A": "b"})
	err := hook(rootfs, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")
}

func TestInjectAuthorizedKeys_RejectsPathTraversal(t *testing.T) {
	t.Parallel()

	rootfs := t.TempDir()
	hook := InjectAuthorizedKeys("ssh-ed25519 AAAA test", WithKeyUser("../../root", 0, 0))
	err := hook(rootfs, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "path traversal")
}

func TestInjectEnvFile_RejectsInvalidKeyNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
	}{
		{"semicolon injection", "FOO;rm -rf /"},
		{"space in key", "FOO BAR"},
		{"starts with digit", "1BAD"},
		{"contains equals", "FOO=BAR"},
		{"empty key", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rootfs := t.TempDir()
			hook := InjectEnvFile("/etc/env", map[string]string{tt.key: "value"})
			err := hook(rootfs, nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), "invalid environment variable name")
		})
	}
}

func TestShellEscape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "''",
		},
		{
			name:     "simple string",
			input:    "hello",
			expected: "'hello'",
		},
		{
			name:     "string with spaces",
			input:    "hello world",
			expected: "'hello world'",
		},
		{
			name:     "string with single quote",
			input:    "it's",
			expected: "'it'\\''s'",
		},
		{
			name:     "string with multiple single quotes",
			input:    "it's a 'test'",
			expected: "'it'\\''s a '\\''test'\\'''",
		},
		{
			name:     "string with double quotes",
			input:    `say "hi"`,
			expected: `'say "hi"'`,
		},
		{
			name:     "string with backslash",
			input:    `path\to\file`,
			expected: `'path\to\file'`,
		},
		{
			name:     "string with dollar sign",
			input:    "$HOME",
			expected: "'$HOME'",
		},
		{
			name:     "string with newline",
			input:    "line1\nline2",
			expected: "'line1\nline2'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.expected, shellEscape(tt.input))
		})
	}
}
