// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestGenerateKeyPair_CreatesValidFiles(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()

	privPath, pubPath, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	// Verify private key file exists with correct permissions.
	privInfo, err := os.Stat(privPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), privInfo.Mode().Perm())
	assert.Equal(t, filepath.Join(keyDir, privateKeyFileName), privPath)

	// Verify public key file exists.
	pubInfo, err := os.Stat(pubPath)
	require.NoError(t, err)
	assert.False(t, pubInfo.IsDir())
	assert.Equal(t, filepath.Join(keyDir, publicKeyFileName), pubPath)

	// Verify private key content is PEM-encoded.
	privData, err := os.ReadFile(privPath)
	require.NoError(t, err)
	assert.Contains(t, string(privData), "BEGIN EC PRIVATE KEY")
	assert.Contains(t, string(privData), "END EC PRIVATE KEY")

	// Verify public key content starts with the expected key type.
	pubData, err := os.ReadFile(pubPath)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(pubData), "ecdsa-sha2-nistp256 "),
		"public key should be in SSH authorized_keys format")
}

func TestGenerateKeyPair_OverwritesExistingKeys(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()

	// Generate first pair.
	_, pubPath1, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	firstPub, err := os.ReadFile(pubPath1)
	require.NoError(t, err)

	// Generate second pair (overwrites).
	_, pubPath2, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	secondPub, err := os.ReadFile(pubPath2)
	require.NoError(t, err)

	// The keys should be different (new generation each time).
	assert.NotEqual(t, string(firstPub), string(secondPub),
		"regenerated keys should be different")
}

func TestGenerateKeyPair_ParseableBySSH(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()

	privPath, pubPath, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	// Parse private key with x/crypto/ssh.
	privData, err := os.ReadFile(privPath)
	require.NoError(t, err)

	signer, err := gossh.ParsePrivateKey(privData)
	require.NoError(t, err, "private key should be parseable by x/crypto/ssh")
	assert.NotNil(t, signer)

	// Parse public key from the authorized_keys format.
	pubData, err := os.ReadFile(pubPath)
	require.NoError(t, err)

	pubKey, _, _, _, err := gossh.ParseAuthorizedKey(pubData)
	require.NoError(t, err, "public key should be parseable from authorized_keys format")
	assert.NotNil(t, pubKey)

	// The public keys from both should match.
	assert.Equal(t, signer.PublicKey().Marshal(), pubKey.Marshal(),
		"public key derived from private key should match the public key file")
}

func TestGetPublicKeyContent(t *testing.T) {
	t.Parallel()

	keyDir := t.TempDir()

	_, pubPath, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	content, err := GetPublicKeyContent(pubPath)
	require.NoError(t, err)

	assert.NotEmpty(t, content)
	assert.True(t, strings.HasPrefix(content, "ecdsa-sha2-nistp256 "),
		"public key content should start with key type")
	// The content returned should end with a newline (SSH authorized_keys format).
	assert.True(t, strings.HasSuffix(content, "\n"),
		"public key content should end with newline")
}

func TestGetPublicKeyContent_NonExistentFile(t *testing.T) {
	t.Parallel()

	_, err := GetPublicKeyContent("/nonexistent/path/ssh_key.pub")
	assert.Error(t, err)
}

func TestGenerateKeyPair_CreatesKeyDirectory(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	keyDir := filepath.Join(tmpDir, "nested", "keys")

	privPath, pubPath, err := GenerateKeyPair(keyDir)
	require.NoError(t, err)

	assert.FileExists(t, privPath)
	assert.FileExists(t, pubPath)
}

func TestGenerateHostKeyPair_Success(t *testing.T) {
	t.Parallel()

	pemBytes, pubKey, err := GenerateHostKeyPair()
	require.NoError(t, err)

	// PEM should be parseable.
	block, rest := pem.Decode(pemBytes)
	require.NotNil(t, block, "PEM block should not be nil")
	assert.Equal(t, "EC PRIVATE KEY", block.Type)
	assert.Empty(t, rest, "no trailing data after PEM block")

	// PEM should be parseable as an SSH private key.
	signer, err := gossh.ParsePrivateKey(pemBytes)
	require.NoError(t, err)
	assert.NotNil(t, signer)

	// Public key should be non-nil and ECDSA P-256.
	require.NotNil(t, pubKey)
	assert.Equal(t, "ecdsa-sha2-nistp256", pubKey.Type())
}

func TestGenerateHostKeyPair_Unique(t *testing.T) {
	t.Parallel()

	pem1, pub1, err := GenerateHostKeyPair()
	require.NoError(t, err)

	pem2, pub2, err := GenerateHostKeyPair()
	require.NoError(t, err)

	assert.NotEqual(t, pem1, pem2, "private keys should differ")
	assert.NotEqual(t, pub1.Marshal(), pub2.Marshal(), "public keys should differ")
}

func TestGenerateHostKeyPair_RoundTrip(t *testing.T) {
	t.Parallel()

	pemBytes, pubKey, err := GenerateHostKeyPair()
	require.NoError(t, err)

	// Parse the PEM back and verify the public key matches.
	signer, err := gossh.ParsePrivateKey(pemBytes)
	require.NoError(t, err)

	signerPub := signer.PublicKey()
	assert.Equal(t, pubKey.Type(), signerPub.Type())
	assert.Equal(t, pubKey.Marshal(), signerPub.Marshal())
}
