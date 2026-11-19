// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

const (
	// admissionIOTimeout bounds every raw read and handshake in the
	// admission tests so a regression fails instead of hanging.
	admissionIOTimeout = 5 * time.Second

	// sshBannerPrefix is what the server sends right after accepting a
	// connection, before any client bytes.
	sshBannerPrefix = "SSH-2.0-"
)

// dialRaw opens a TCP connection and registers its cleanup.
func dialRaw(t *testing.T, addr string) net.Conn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, admissionIOTimeout)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

// readBanner reports whether the server sent its SSH version banner on
// conn within admissionIOTimeout. A closed connection yields an error.
func readBanner(conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(admissionIOTimeout)); err != nil {
		return fmt.Errorf("set read deadline: %w", err)
	}

	buf := make([]byte, len(sshBannerPrefix))
	if _, err := io.ReadFull(conn, buf); err != nil {
		return fmt.Errorf("read banner: %w", err)
	}
	if string(buf) != sshBannerPrefix {
		return fmt.Errorf("unexpected banner %q", buf)
	}

	return nil
}

// dialSSHBounded performs the SSH handshake over a connection with an
// explicit transport deadline; ssh.ClientConfig.Timeout only covers the
// TCP dial, not the handshake.
func dialSSHBounded(t *testing.T, addr string, signer ssh.Signer) *ssh.Client {
	t.Helper()

	conn := dialRaw(t, addr)
	require.NoError(t, conn.SetDeadline(time.Now().Add(admissionIOTimeout)))

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User: "testuser",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		//nolint:gosec // Test code; host key verification not needed.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Time{}))

	client := ssh.NewClient(sshConn, chans, reqs)
	t.Cleanup(func() { _ = client.Close() })

	return client
}

// saturate opens maxConcurrentConns raw connections and waits until the
// server has admitted every one of them (each received a banner).
func saturate(t *testing.T, addr string) []net.Conn {
	t.Helper()

	conns := make([]net.Conn, 0, maxConcurrentConns)
	for range maxConcurrentConns {
		conn := dialRaw(t, addr)
		require.NoError(t, readBanner(conn))
		conns = append(conns, conn)
	}

	return conns
}

func TestConcurrentConnectionsBeyondFour(t *testing.T) {
	t.Parallel()

	signer, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	const clients = 5

	held := make([]*ssh.Client, 0, clients)
	for range clients {
		held = append(held, dialSSHBounded(t, addr, signer))
	}

	// Every client must stay functional while all the others are open.
	for i, client := range held {
		session, err := client.NewSession()
		require.NoError(t, err, "client %d", i)

		out, err := session.CombinedOutput(fmt.Sprintf("echo client-%d", i))
		_ = session.Close()
		require.NoError(t, err, "client %d", i)
		assert.Equal(t, fmt.Sprintf("client-%d\n", i), string(out))
	}
}

func TestConnectionOverLimitClosedPromptly(t *testing.T) {
	t.Parallel()

	_, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	saturate(t, addr)

	extra := dialRaw(t, addr)
	require.NoError(t, extra.SetReadDeadline(time.Now().Add(admissionIOTimeout)))

	start := time.Now()
	buf := make([]byte, 1)
	_, err := extra.Read(buf)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.NotErrorIs(t, err, os.ErrDeadlineExceeded,
		"over-limit connection timed out instead of being closed")
	assert.Less(t, elapsed, admissionIOTimeout)
}

func TestConnectionAdmittedAfterSlotFreed(t *testing.T) {
	t.Parallel()

	_, pubKey := generateTestKeyPair(t)
	_, addr := startTestServer(t, pubKey)

	conns := saturate(t, addr)

	// At capacity: a further connection gets no banner.
	require.Error(t, readBanner(dialRaw(t, addr)))

	require.NoError(t, conns[0].Close())

	// The slot is released asynchronously once the server notices the
	// close, so poll for admission with a bound.
	require.Eventually(t, func() bool {
		conn, err := net.DialTimeout("tcp", addr, admissionIOTimeout)
		if err != nil {
			return false
		}
		defer func() { _ = conn.Close() }()

		return readBanner(conn) == nil
	}, 10*time.Second, 50*time.Millisecond)
}

func TestCloseAtSaturationDoesNotWedgeServe(t *testing.T) {
	t.Parallel()

	_, pubKey := generateTestKeyPair(t)
	srv, err := New(Config{AuthorizedKeys: []ssh.PublicKey{pubKey}})
	require.NoError(t, err)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()

	conns := saturate(t, ln.Addr().String())

	// Keep one more connection pending past the limit while closing.
	_ = dialRaw(t, ln.Addr().String())

	closed := make(chan struct{})
	go func() {
		srv.Close()
		close(closed)
	}()

	select {
	case err := <-served:
		assert.NoError(t, err)
	case <-time.After(admissionIOTimeout):
		t.Fatal("Serve did not return after Close at saturation")
	}

	// Close waits for admitted connections; release them so it finishes.
	for _, conn := range conns {
		_ = conn.Close()
	}

	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not finish after admitted connections were closed")
	}
}
