// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package boot

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()

	assert.Equal(t, "/workspace", cfg.workspaceMountPoint)
	assert.Equal(t, "workspace", cfg.workspaceTag)
	assert.Equal(t, 1000, cfg.workspaceUID)
	assert.Equal(t, 1000, cfg.workspaceGID)
	assert.Equal(t, 5, cfg.mountRetries)
	assert.Equal(t, 22, cfg.sshPort)
	assert.Equal(t, "/home/sandbox/.ssh/authorized_keys", cfg.sshKeysPath)
	assert.Equal(t, "/etc/sandbox-env", cfg.envFilePath)
	assert.Equal(t, "sandbox", cfg.userName)
	assert.Equal(t, "/home/sandbox", cfg.userHome)
	assert.Equal(t, "/bin/bash", cfg.userShell)
	assert.Equal(t, uint32(1000), cfg.userUID)
	assert.Equal(t, uint32(1000), cfg.userGID)
	assert.True(t, cfg.lockdownRoot)
}

func TestWithWorkspace(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithWorkspace("/mnt/data", "data", 500, 500).apply(cfg)

	assert.Equal(t, "/mnt/data", cfg.workspaceMountPoint)
	assert.Equal(t, "data", cfg.workspaceTag)
	assert.Equal(t, 500, cfg.workspaceUID)
	assert.Equal(t, 500, cfg.workspaceGID)
}

func TestWithUser(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithUser("dev", "/home/dev", "/bin/zsh", 2000, 2000).apply(cfg)

	assert.Equal(t, "dev", cfg.userName)
	assert.Equal(t, "/home/dev", cfg.userHome)
	assert.Equal(t, "/bin/zsh", cfg.userShell)
	assert.Equal(t, uint32(2000), cfg.userUID)
	assert.Equal(t, uint32(2000), cfg.userGID)
}

func TestWithSSHPort(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithSSHPort(2222).apply(cfg)

	assert.Equal(t, 2222, cfg.sshPort)
}

func TestWithMountRetries(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithMountRetries(10).apply(cfg)

	assert.Equal(t, 10, cfg.mountRetries)
}

func TestWithSSHKeysPath(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithSSHKeysPath("/root/.ssh/authorized_keys").apply(cfg)

	assert.Equal(t, "/root/.ssh/authorized_keys", cfg.sshKeysPath)
}

func TestWithEnvFilePath(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithEnvFilePath("/etc/custom-env").apply(cfg)

	assert.Equal(t, "/etc/custom-env", cfg.envFilePath)
}

func TestWithLockdownRoot(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	WithLockdownRoot(false).apply(cfg)

	assert.False(t, cfg.lockdownRoot)
}

func TestOptionComposition(t *testing.T) {
	t.Parallel()
	cfg := defaultConfig()
	opts := []Option{
		WithSSHPort(2222),
		WithUser("dev", "/home/dev", "/bin/zsh", 2000, 2000),
		WithLockdownRoot(false),
		WithMountRetries(3),
	}
	for _, o := range opts {
		o.apply(cfg)
	}

	// Last wins for scalars.
	assert.Equal(t, 2222, cfg.sshPort)
	assert.Equal(t, "dev", cfg.userName)
	assert.False(t, cfg.lockdownRoot)
	assert.Equal(t, 3, cfg.mountRetries)
	// Unchanged defaults.
	assert.Equal(t, "/workspace", cfg.workspaceMountPoint)
	assert.Equal(t, "/etc/sandbox-env", cfg.envFilePath)
}

func TestParseAuthorizedKeys(t *testing.T) {
	t.Parallel()

	t.Run("valid key", func(t *testing.T) {
		t.Parallel()
		key, pubKeyStr := generateTestKey(t)
		_ = key

		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		require.NoError(t, os.WriteFile(path, []byte(pubKeyStr+"\n"), 0o600))

		keys, err := ParseAuthorizedKeys(path)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()
		_, err := ParseAuthorizedKeys("/nonexistent/authorized_keys")
		assert.Error(t, err)
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		require.NoError(t, os.WriteFile(path, []byte(""), 0o600))

		_, err := ParseAuthorizedKeys(path)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no valid keys")
	})

	t.Run("invalid key skipped", func(t *testing.T) {
		t.Parallel()
		_, pubKeyStr := generateTestKey(t)

		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		content := "not-a-valid-key\n" + pubKeyStr + "\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		keys, err := ParseAuthorizedKeys(path)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})

	t.Run("comments skipped", func(t *testing.T) {
		t.Parallel()
		_, pubKeyStr := generateTestKey(t)

		dir := t.TempDir()
		path := filepath.Join(dir, "authorized_keys")
		content := "# comment\n" + pubKeyStr + "\n"
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		keys, err := ParseAuthorizedKeys(path)
		require.NoError(t, err)
		assert.Len(t, keys, 1)
	})
}

// generateTestKey creates an ECDSA key pair and returns the signer and
// the authorized_keys-formatted public key string.
func generateTestKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	pubKeyStr := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	return signer, pubKeyStr
}
