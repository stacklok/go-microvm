// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// generateTestKeyPair creates an ECDSA P-256 key pair for testing and
// returns both the signer (client side) and public key (server side).
func generateTestKeyPair(t *testing.T) (ssh.Signer, ssh.PublicKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)

	return signer, signer.PublicKey()
}

// startTestServer creates and starts an SSH server on a random port with
// the supplied authorized key. It returns the server and the listener
// address. The listener address is captured before Serve is called to
// avoid data races on the server's internal listener field.
func startTestServer(t *testing.T, authorizedKey ssh.PublicKey) (*Server, string) {
	t.Helper()

	workDir := t.TempDir()

	srv, err := New(Config{
		Port:           0,
		AuthorizedKeys: []ssh.PublicKey{authorizedKey},
		Env:            []string{"PATH=/usr/bin:/bin"},
		DefaultUID:     uint32(os.Getuid()),
		DefaultGID:     uint32(os.Getgid()),
		DefaultUser:    "testuser",
		DefaultHome:    os.TempDir(),
		DefaultShell:   "/bin/sh",
		DefaultWorkDir: workDir,
		Logger:         slog.Default(),
	})
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := ln.Addr().String()

	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		srv.Close()
	})

	return srv, addr
}

// startTestServerWithConfig creates and starts an SSH server with a
// custom Config. Returns the server and its listen address.
func startTestServerWithConfig(t *testing.T, cfg Config) (*Server, string) {
	t.Helper()

	srv, err := New(cfg)
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := ln.Addr().String()

	go func() {
		_ = srv.Serve(ln)
	}()

	t.Cleanup(func() {
		srv.Close()
	})

	return srv, addr
}

// dialSSH establishes an SSH client connection to the server using the
// given signer for authentication.
func dialSSH(t *testing.T, addr string, signer ssh.Signer) *ssh.Client {
	t.Helper()

	config := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		//nolint:gosec // Test code; host key verification not needed.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	client, err := ssh.Dial("tcp", addr, config)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = client.Close()
	})

	return client
}

func TestAuthorizedKeyAccepted(t *testing.T) {
	t.Parallel()

	signer, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	client := dialSSH(t, addr, signer)
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = session.Run("true")
	assert.NoError(t, err)
}

func TestUnauthorizedKeyRejected(t *testing.T) {
	t.Parallel()

	_, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	// Generate a different key pair for the client.
	wrongSigner, _ := generateTestKeyPair(t)

	config := &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(wrongSigner),
		},
		//nolint:gosec // Test code; host key verification not needed.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	_, err := ssh.Dial("tcp", addr, config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ssh: handshake failed")
}

func TestExecCommand(t *testing.T) {
	t.Parallel()

	signer, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	client := dialSSH(t, addr, signer)
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	output, err := session.CombinedOutput("echo hello world")
	require.NoError(t, err)
	assert.Equal(t, "hello world\n", string(output))
}

func TestExecCommandEnv(t *testing.T) {
	t.Parallel()

	signer, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	client := dialSSH(t, addr, signer)
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	// TERM is in the allowlist.
	err = session.Setenv("TERM", "xterm-256color")
	require.NoError(t, err)

	output, err := session.CombinedOutput("echo $TERM")
	require.NoError(t, err)
	assert.Equal(t, "xterm-256color\n", string(output))
}

func TestExitCode(t *testing.T) {
	t.Parallel()

	signer, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	client := dialSSH(t, addr, signer)
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = session.Run("exit 42")
	require.Error(t, err)

	exitErr, ok := err.(*ssh.ExitError)
	require.True(t, ok, "expected *ssh.ExitError, got %T", err)
	assert.Equal(t, 42, exitErr.ExitStatus())
}

func TestNonSessionChannelRejected(t *testing.T) {
	t.Parallel()

	signer, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	client := dialSSH(t, addr, signer)

	// Attempt to open a non-session channel type.
	_, _, err := client.OpenChannel("direct-tcpip", nil)
	require.Error(t, err)

	openChErr, ok := err.(*ssh.OpenChannelError)
	require.True(t, ok, "expected *ssh.OpenChannelError, got %T", err)
	assert.Equal(t, ssh.UnknownChannelType, openChErr.Reason)
}

func TestDefaultWorkDir(t *testing.T) {
	t.Parallel()

	signer, pubKey := generateTestKeyPair(t)

	workDir := t.TempDir()

	_, addr := startTestServerWithConfig(t, Config{
		Port:           0,
		AuthorizedKeys: []ssh.PublicKey{pubKey},
		Env:            []string{"PATH=/usr/bin:/bin"},
		DefaultUID:     uint32(os.Getuid()),
		DefaultGID:     uint32(os.Getgid()),
		DefaultUser:    "testuser",
		DefaultHome:    os.TempDir(),
		DefaultShell:   "/bin/sh",
		DefaultWorkDir: workDir,
		Logger:         slog.Default(),
	})

	client := dialSSH(t, addr, signer)

	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	output, err := session.CombinedOutput("pwd")
	require.NoError(t, err)

	// Resolve symlinks for comparison (e.g. /tmp may be a symlink).
	expected, err := filepath.EvalSymlinks(workDir)
	require.NoError(t, err)

	assert.Equal(t, expected, strings.TrimSpace(string(output)))
}

func TestDefaultWorkDirFallback(t *testing.T) {
	t.Parallel()

	signer, pubKey := generateTestKeyPair(t)

	homeDir := t.TempDir()

	// DefaultWorkDir is left empty so the server falls back to DefaultHome.
	_, addr := startTestServerWithConfig(t, Config{
		Port:           0,
		AuthorizedKeys: []ssh.PublicKey{pubKey},
		Env:            []string{"PATH=/usr/bin:/bin"},
		DefaultUID:     uint32(os.Getuid()),
		DefaultGID:     uint32(os.Getgid()),
		DefaultUser:    "testuser",
		DefaultHome:    homeDir,
		DefaultShell:   "/bin/sh",
		DefaultWorkDir: "",
		Logger:         slog.Default(),
	})

	client := dialSSH(t, addr, signer)

	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	output, err := session.CombinedOutput("pwd")
	require.NoError(t, err)

	// Resolve symlinks for comparison.
	expected, err := filepath.EvalSymlinks(homeDir)
	require.NoError(t, err)

	assert.Equal(t, expected, strings.TrimSpace(string(output)))
}

func TestAgentForwardingDisabled(t *testing.T) {
	t.Parallel()

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
		AgentForwarding: false,
		Logger:          slog.Default(),
	})

	client := dialSSH(t, addr, signer)

	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	// Request agent forwarding via the real API — should be rejected.
	err = agent.RequestAgentForwarding(session)
	assert.Error(t, err, "agent forwarding should be rejected when disabled")
}

func TestAgentForwardingEnabled(t *testing.T) {
	t.Parallel()

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

	client := dialSSH(t, addr, signer)

	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	// Request agent forwarding via the real API — should be accepted.
	err = agent.RequestAgentForwarding(session)
	require.NoError(t, err, "agent forwarding should be accepted when enabled")

	// Verify the flag was set by running a command on a second session.
	session2, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session2.Close() }()

	output, err := session2.CombinedOutput("echo ${SSH_AUTH_SOCK:-unset}")
	require.NoError(t, err)
	result := strings.TrimSpace(string(output))
	assert.Contains(t, result, "/tmp/ssh-", "agent socket should be set on connection after forwarding request")
}

func TestAgentSocketCreated(t *testing.T) {
	t.Parallel()

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

	client := dialSSH(t, addr, signer)

	// Request agent forwarding and run a command on the same session,
	// which is the real client flow: auth-agent-req arrives before exec.
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = agent.RequestAgentForwarding(session)
	require.NoError(t, err)

	output, err := session.CombinedOutput("echo $SSH_AUTH_SOCK")
	require.NoError(t, err)

	sockPath := strings.TrimSpace(string(output))
	assert.NotEmpty(t, sockPath, "SSH_AUTH_SOCK should be set when agent forwarding is enabled")
	assert.Contains(t, sockPath, "/tmp/ssh-", "agent socket should be in /tmp/ssh-*")
}

func TestAgentForwardingEndToEnd(t *testing.T) {
	t.Parallel()

	// 1. Create a test key and add it to an in-memory agent.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	keyring := agent.NewKeyring()
	require.NoError(t, keyring.Add(agent.AddedKey{PrivateKey: ecKey}))

	// 2. Start server with agent forwarding enabled.
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
		DefaultWorkDir:  t.TempDir(),
		AgentForwarding: true,
		Logger:          slog.Default(),
	})

	// 3. Connect SSH client.
	client := dialSSH(t, addr, signer)

	// 4. Register handler for auth-agent@openssh.com channels BEFORE
	//    requesting forwarding — otherwise the server's channel open
	//    will be rejected.
	agentChans := client.HandleChannelOpen("auth-agent@openssh.com")
	go func() {
		for newCh := range agentChans {
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(reqs)
			go func() {
				agent.ServeAgent(keyring, ch)
				_ = ch.Close()
			}()
		}
	}()

	// 5. Open a session, request forwarding, run ssh-add -l.
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = agent.RequestAgentForwarding(session)
	require.NoError(t, err)

	output, err := session.CombinedOutput("ssh-add -l")
	require.NoError(t, err)

	result := string(output)
	assert.NotContains(t, result, "The agent has no identities")
	assert.NotContains(t, result, "Could not open a connection")
	assert.Contains(t, result, "ECDSA", "expected forwarded ECDSA key in ssh-add output")
}

func TestAgentForwardingEndToEnd_NoClientHandler(t *testing.T) {
	t.Parallel()

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
		DefaultWorkDir:  t.TempDir(),
		AgentForwarding: true,
		Logger:          slog.Default(),
	})

	client := dialSSH(t, addr, signer)

	// Do NOT register HandleChannelOpen — the proxy channel will be rejected.

	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	err = agent.RequestAgentForwarding(session)
	require.NoError(t, err)

	output, err := session.CombinedOutput("ssh-add -l 2>&1")
	result := strings.TrimSpace(string(output))

	// Without a client-side handler, ssh-add should fail.
	if err == nil {
		// Some versions of ssh-add exit 0 but report no agent.
		assert.True(t,
			strings.Contains(result, "Could not open a connection") ||
				strings.Contains(result, "The agent has no identities") ||
				strings.Contains(result, "Error connecting to agent") ||
				strings.Contains(result, "error"),
			"ssh-add should fail without client-side agent handler, got: %s", result,
		)
	}
	// If err != nil, the command exited non-zero — that's the expected case.
}

func TestNoSocketWithoutForwardingRequest(t *testing.T) {
	t.Parallel()

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

	client := dialSSH(t, addr, signer)

	// Do NOT request agent forwarding.

	// Run a command that checks if SSH_AUTH_SOCK is set.
	session, err := client.NewSession()
	require.NoError(t, err)
	defer func() { _ = session.Close() }()

	output, err := session.CombinedOutput("echo ${SSH_AUTH_SOCK:-unset}")
	require.NoError(t, err)

	result := strings.TrimSpace(string(output))
	assert.Equal(t, "unset", result, "SSH_AUTH_SOCK should not be set without forwarding request")
}
