// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package ssh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// sshWaitPollInterval is the interval between SSH readiness polls.
	sshWaitPollInterval = 2 * time.Second

	// defaultSSHTimeout is the default timeout for SSH connection attempts.
	defaultSSHTimeout = 10 * time.Second
)

// Client provides a high-level SSH interface for communicating with a
// microVM guest.
type Client struct {
	host    string
	port    uint16
	user    string
	keyPath string
}

// NewClient creates a new SSH Client configured to connect to the given
// host and port using the specified user and private key file.
func NewClient(host string, port uint16, user, keyPath string) *Client {
	return &Client{
		host:    host,
		port:    port,
		user:    user,
		keyPath: keyPath,
	}
}

// Run executes a command on the remote host and returns its combined
// stdout and stderr output.
func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	session, client, err := c.newSession(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = client.Close() }()
	defer func() { _ = session.Close() }()

	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = &output

	if err := session.Run(cmd); err != nil {
		return output.String(), fmt.Errorf("ssh command %q: %w (output: %s)",
			cmd, err, output.String())
	}

	return output.String(), nil
}

// RunSudo executes a command on the remote host with elevated privileges
// using "doas". Returns the combined stdout and stderr output.
func (c *Client) RunSudo(ctx context.Context, cmd string) (string, error) {
	return c.Run(ctx, "doas "+cmd)
}

// RunStream executes a command on the remote host and streams its stdout
// and stderr to the provided writers. It blocks until the command completes.
func (c *Client) RunStream(ctx context.Context, cmd string, stdout, stderr io.Writer) error {
	session, client, err := c.newSession(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	defer func() { _ = session.Close() }()

	session.Stdout = stdout
	session.Stderr = stderr

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("ssh stream command %q: %w", cmd, err)
	}

	return nil
}

// CopyTo copies a local file to the remote host at the specified path
// using cat over SSH. The file permissions on the remote side are set to
// the provided mode.
func (c *Client) CopyTo(ctx context.Context, localPath, remotePath string, mode os.FileMode) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read local file %s: %w", localPath, err)
	}

	// Use cat to write the file content, then chmod to set permissions.
	cmd := fmt.Sprintf("cat > %s && chmod %o %s",
		ShellEscape(remotePath), mode, ShellEscape(remotePath))

	session, client, err := c.newSession(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	defer func() { _ = session.Close() }()

	session.Stdin = bytes.NewReader(data)

	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = &output

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("copy to %s: %w (output: %s)", remotePath, err, output.String())
	}

	return nil
}

// CopyFrom copies a remote file to the local filesystem.
func (c *Client) CopyFrom(ctx context.Context, remotePath, localPath string) error {
	cmd := fmt.Sprintf("cat %s", ShellEscape(remotePath))

	output, err := c.Run(ctx, cmd)
	if err != nil {
		return fmt.Errorf("copy from %s: %w", remotePath, err)
	}

	if err := os.WriteFile(localPath, []byte(output), 0o644); err != nil {
		return fmt.Errorf("write local file %s: %w", localPath, err)
	}

	return nil
}

// WaitForReady polls the SSH server until a connection can be established
// or the context is cancelled. This is used to wait for the guest VM's
// SSH server to come up after boot.
func (c *Client) WaitForReady(ctx context.Context) error {
	slog.Info("waiting for SSH to become ready",
		"host", c.host,
		"port", c.port,
		"user", c.user,
	)

	ticker := time.NewTicker(sshWaitPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context cancelled waiting for SSH: %w", ctx.Err())
		case <-ticker.C:
			if err := c.probe(ctx); err != nil {
				slog.Debug("SSH not ready yet", "error", err)
				continue
			}
			slog.Info("SSH is ready",
				"host", c.host,
				"port", c.port,
			)
			return nil
		}
	}
}

// probe attempts a single SSH connection to verify the server is accepting
// connections and authenticating correctly.
func (c *Client) probe(ctx context.Context) error {
	session, client, err := c.newSession(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	defer func() { _ = session.Close() }()

	// Run a trivial command to verify the connection works end-to-end.
	return session.Run("true")
}

// newSession creates a new SSH session to the remote host.
func (c *Client) newSession(ctx context.Context) (*ssh.Session, *ssh.Client, error) {
	config, err := c.sshConfig()
	if err != nil {
		return nil, nil, err
	}

	addr := fmt.Sprintf("%s:%d", c.host, c.port)

	// Use a dialer with context support for cancellation.
	dialer := net.Dialer{Timeout: defaultSSHTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		_ = client.Close()
		return nil, nil, fmt.Errorf("create ssh session: %w", err)
	}

	return session, client, nil
}

// sshConfig builds an ssh.ClientConfig from the client's settings.
func (c *Client) sshConfig() (*ssh.ClientConfig, error) {
	keyData, err := os.ReadFile(c.keyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", c.keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key %s: %w", c.keyPath, err)
	}

	return &ssh.ClientConfig{
		User: c.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		//nolint:gosec // We trust the VM we just created; host key checking is unnecessary.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         defaultSSHTimeout,
	}, nil
}

// ShellEscape escapes a string for safe use in a shell command.
// It wraps the string in single quotes, escaping any embedded single quotes.
func ShellEscape(s string) string {
	// Replace single quotes with the sequence: end-quote, escaped-quote, start-quote.
	escaped := strings.ReplaceAll(s, "'", `'\''`)
	return "'" + escaped + "'"
}
