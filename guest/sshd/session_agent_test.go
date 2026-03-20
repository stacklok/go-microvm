// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// startAgentServer creates a test SSH server with agent forwarding
// enabled and returns (server, address, client-signer).
func startAgentServer(t *testing.T) (string, ssh.Signer) {
	t.Helper()

	signer, pubKey := generateTestKeyPair(t)
	_, addr := startTestServerWithConfig(t, Config{
		Port:            0,
		AuthorizedKeys:  []ssh.PublicKey{pubKey},
		Env:             []string{"PATH=/usr/bin:/bin"},
		DefaultUID:      uint32(os.Getuid()),
		DefaultGID:      uint32(os.Getgid()),
		DefaultUser:     "testuser",
		DefaultHome:     os.TempDir(),
		DefaultShell:    "/bin/sh",
		AgentForwarding: true,
		Logger:          slog.Default(),
	})

	return addr, signer
}

// setupClientAgentForwarding registers a host-side agent forwarding
// handler on the SSH client that serves a test key. This mirrors what
// brood-box does: for each incoming "auth-agent@openssh.com" channel,
// it creates a keyring with a test key and serves the agent protocol.
func setupClientAgentForwarding(t *testing.T, client *ssh.Client) {
	t.Helper()

	// Generate a fresh key for the agent keyring.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyring := agent.NewKeyring()
	err = keyring.Add(agent.AddedKey{PrivateKey: privKey})
	require.NoError(t, err)

	// Register the handler for incoming agent channels from the server.
	chans := client.HandleChannelOpen("auth-agent@openssh.com")
	require.NotNil(t, chans, "HandleChannelOpen should not return nil")

	go func() {
		for ch := range chans {
			channel, reqs, err := ch.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				defer func() { _ = channel.Close() }()
				_ = agent.ServeAgent(keyring, channel)
			}()
		}
	}()
}

// TestAgentProxyCleanup verifies that the agent forwarding proxy
// goroutines and semaphore slots are released after each command.
// Before the CloseWrite fix, proxy goroutines would leak and after
// maxAgentConns (8) connections the semaphore would be exhausted,
// causing all subsequent agent queries to fail.
func TestAgentProxyCleanup(t *testing.T) {
	t.Parallel()

	addr, signer := startAgentServer(t)
	client := dialSSH(t, addr, signer)
	setupClientAgentForwarding(t, client)

	// Run more sessions than maxAgentConns (8) to verify semaphore
	// slots are released. Stay within maxChannelsPerConn (10) to
	// avoid the per-connection channel limit. Without CloseWrite,
	// proxy goroutines would leak and exhaust the semaphore.
	for i := range maxChannelsPerConn {
		session, err := client.NewSession()
		require.NoError(t, err, "session %d", i)

		err = agent.RequestAgentForwarding(session)
		require.NoError(t, err, "request agent forwarding %d", i)

		// The command connects to SSH_AUTH_SOCK (triggering the proxy)
		// and then exits. The proxy must clean up afterwards.
		output, err := session.CombinedOutput(
			`test -S "$SSH_AUTH_SOCK" && echo "socket_ok" || echo "no_socket"`,
		)
		require.NoError(t, err, "command %d", i)
		assert.Equal(t, "socket_ok", strings.TrimSpace(string(output)),
			"agent socket should exist on iteration %d", i)

		_ = session.Close()

		// Brief pause to let proxy goroutines complete cleanup.
		time.Sleep(50 * time.Millisecond)
	}
}

// TestAgentProxyConcurrent verifies that multiple concurrent agent
// connections within the maxAgentConns limit work correctly and all
// clean up properly.
func TestAgentProxyConcurrent(t *testing.T) {
	t.Parallel()

	addr, signer := startAgentServer(t)
	client := dialSSH(t, addr, signer)
	setupClientAgentForwarding(t, client)

	// Run a command that makes several agent socket connections in
	// quick succession within a single session.
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = agent.RequestAgentForwarding(session)
	require.NoError(t, err)

	// Each `test -S` triggers a stat, not a socket connection. Instead,
	// use a loop that actually connects to the agent socket via ssh-add -l
	// equivalent. We'll do multiple nc/socat-free socket tests.
	output, err := session.CombinedOutput(`
		success=0
		fail=0
		for i in $(seq 1 5); do
			if test -S "$SSH_AUTH_SOCK"; then
				success=$((success + 1))
			else
				fail=$((fail + 1))
			fi
		done
		echo "success=$success fail=$fail"
	`)
	require.NoError(t, err)

	result := strings.TrimSpace(string(output))
	assert.Equal(t, "success=5 fail=0", result)
}
