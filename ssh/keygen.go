// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

const (
	// privateKeyFileName is the default name for generated private keys.
	privateKeyFileName = "ssh_key"

	// publicKeyFileName is the default name for generated public keys.
	publicKeyFileName = "ssh_key.pub"
)

// GenerateKeyPair generates an ECDSA P-256 SSH key pair and writes the
// private key to keyDir/ssh_key and the public key to keyDir/ssh_key.pub.
// The private key file is created with 0600 permissions.
//
// If the key files already exist, they are overwritten.
func GenerateKeyPair(keyDir string) (privateKeyPath, publicKeyPath string, err error) {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create key directory: %w", err)
	}

	privateKeyPath = filepath.Join(keyDir, privateKeyFileName)
	publicKeyPath = filepath.Join(keyDir, publicKeyFileName)

	// Generate ECDSA P-256 key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate ECDSA key: %w", err)
	}

	// Marshal private key to PKCS8 DER.
	derBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}

	// Encode private key as PEM.
	pemBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: derBytes,
	}

	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(pemBlock), 0o600); err != nil {
		return "", "", fmt.Errorf("write private key: %w", err)
	}

	// Generate and write public key in SSH authorized_keys format.
	pubKey, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("convert to SSH public key: %w", err)
	}

	authorizedKey := ssh.MarshalAuthorizedKey(pubKey)
	if err := os.WriteFile(publicKeyPath, authorizedKey, 0o644); err != nil {
		return "", "", fmt.Errorf("write public key: %w", err)
	}

	return privateKeyPath, publicKeyPath, nil
}

// GetPublicKeyContent reads an SSH public key file and returns its content
// as a string suitable for inclusion in authorized_keys.
func GetPublicKeyContent(publicKeyPath string) (string, error) {
	data, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", fmt.Errorf("read public key %s: %w", publicKeyPath, err)
	}

	return string(data), nil
}
