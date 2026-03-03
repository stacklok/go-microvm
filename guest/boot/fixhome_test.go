// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package boot

import (
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFixHomeOwnership_FixesPermissions(t *testing.T) {
	t.Parallel()

	u, err := user.Current()
	require.NoError(t, err)
	uid, err := strconv.Atoi(u.Uid)
	require.NoError(t, err)
	gid, err := strconv.Atoi(u.Gid)
	require.NoError(t, err)

	home := t.TempDir()

	// Create .ssh dir with wrong permissions (0755 instead of 0700).
	sshDir := filepath.Join(home, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0o755))

	// Create authorized_keys with wrong permissions (0644 instead of 0600).
	akPath := filepath.Join(sshDir, "authorized_keys")
	require.NoError(t, os.WriteFile(akPath, []byte("ssh-ed25519 AAAA test"), 0o644))

	// Create a non-SSH file that should not get SSH permission enforcement.
	require.NoError(t, os.WriteFile(filepath.Join(home, ".gitconfig"), []byte("[user]"), 0o644))

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	fixHomeOwnership(logger, home, uid, gid)

	// Verify .ssh directory permissions are 0700.
	info, err := os.Stat(sshDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(), ".ssh dir should be 0700")

	// Verify authorized_keys permissions are 0600.
	info, err = os.Stat(akPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "authorized_keys should be 0600")

	// Verify non-SSH file permissions are unchanged.
	info, err = os.Stat(filepath.Join(home, ".gitconfig"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), info.Mode().Perm(), ".gitconfig should be unchanged")
}

func TestFixHomeOwnership_HandlesNestedSSHFiles(t *testing.T) {
	t.Parallel()

	u, err := user.Current()
	require.NoError(t, err)
	uid, err := strconv.Atoi(u.Uid)
	require.NoError(t, err)
	gid, err := strconv.Atoi(u.Gid)
	require.NoError(t, err)

	home := t.TempDir()

	// Create .ssh with a known_hosts file.
	sshDir := filepath.Join(home, ".ssh")
	require.NoError(t, os.MkdirAll(sshDir, 0o755))
	khPath := filepath.Join(sshDir, "known_hosts")
	require.NoError(t, os.WriteFile(khPath, []byte("github.com ..."), 0o644))

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	fixHomeOwnership(logger, home, uid, gid)

	info, err := os.Stat(khPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "known_hosts should be 0600")
}

func TestFixHomeOwnership_MissingHome(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Should not panic on missing directory — just logs a warning.
	fixHomeOwnership(logger, "/nonexistent/home/dir", 1000, 1000)
}

func TestIsSSHPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rel  string
		want bool
	}{
		{".ssh", true},
		{".ssh/authorized_keys", true},
		{".ssh/known_hosts", true},
		{".gitconfig", false},
		{".config/opencode", false},
		{"", false},
		{".sshconfig", false},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.want, isSSHPath(tt.rel), "isSSHPath(%q)", tt.rel)
	}
}
