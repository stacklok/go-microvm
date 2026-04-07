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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"golang.org/x/crypto/ssh"
)

const (
	// sshWaitPollInterval is the interval between SSH readiness polls.
	sshWaitPollInterval = 2 * time.Second

	// defaultSSHTimeout is the default timeout for SSH connection attempts.
	defaultSSHTimeout = 10 * time.Second
)

// remoteSession abstracts the operations needed from an SSH session.
type remoteSession interface {
	Run(cmd string) error
	SetStdout(w io.Writer)
	SetStderr(w io.Writer)
	SetStdin(r io.Reader)
	Close() error
}

// sshSessionAdapter wraps *ssh.Session to implement remoteSession.
type sshSessionAdapter struct {
	sess *ssh.Session
}

func (s *sshSessionAdapter) Run(cmd string) error  { return s.sess.Run(cmd) }
func (s *sshSessionAdapter) SetStdout(w io.Writer) { s.sess.Stdout = w }
func (s *sshSessionAdapter) SetStderr(w io.Writer) { s.sess.Stderr = w }
func (s *sshSessionAdapter) SetStdin(r io.Reader)  { s.sess.Stdin = r }
func (s *sshSessionAdapter) Close() error          { return s.sess.Close() }

// ClientOption configures optional Client behavior.
type ClientOption func(*Client)

// WithHostKey pins the expected SSH host key. When set, the client uses
// ssh.FixedHostKey for host key verification instead of accepting any key.
func WithHostKey(pubKey ssh.PublicKey) ClientOption {
	return func(c *Client) {
		c.expectedHostKey = pubKey
	}
}

// Client provides a high-level SSH interface for communicating with a
// microVM guest.
type Client struct {
	host    string
	port    uint16
	user    string
	keyPath string

	// expectedHostKey, when non-nil, enables host key pinning via
	// ssh.FixedHostKey. When nil, InsecureIgnoreHostKey is used for
	// backward compatibility.
	expectedHostKey ssh.PublicKey

	// readFile reads a file from disk. Defaults to os.ReadFile.
	// Injected for testability.
	readFile func(string) ([]byte, error)

	// writeFile writes a file to disk. Defaults to os.WriteFile.
	// Injected for testability.
	writeFile func(string, []byte, os.FileMode) error

	// createSession creates a remote session and returns a cleanup function.
	// Defaults to real SSH via newSession. Injected for testability.
	createSession func(ctx context.Context) (remoteSession, func(), error)
}

// NewClient creates a new SSH Client configured to connect to the given
// host and port using the specified user and private key file.
// Options are applied after defaults to allow host key pinning, etc.
func NewClient(host string, port uint16, user, keyPath string, opts ...ClientOption) *Client {
	c := &Client{
		host:      host,
		port:      port,
		user:      user,
		keyPath:   keyPath,
		readFile:  os.ReadFile,
		writeFile: os.WriteFile,
	}
	for _, o := range opts {
		o(c)
	}
	c.createSession = func(ctx context.Context) (remoteSession, func(), error) {
		sess, client, err := c.newSession(ctx)
		if err != nil {
			return nil, nil, err
		}
		cleanup := func() {
			_ = sess.Close()
			_ = client.Close()
		}
		return &sshSessionAdapter{sess: sess}, cleanup, nil
	}
	return c
}

// Run executes a command on the remote host and returns its combined
// stdout and stderr output.
func (c *Client) Run(ctx context.Context, cmd string) (string, error) {
	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return "", err
	}
	defer cleanup()
	defer func() { _ = session.Close() }()

	var output bytes.Buffer
	session.SetStdout(&output)
	session.SetStderr(&output)

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
	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	defer func() { _ = session.Close() }()

	session.SetStdout(stdout)
	session.SetStderr(stderr)

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("ssh stream command %q: %w", cmd, err)
	}

	return nil
}

// CopyTo copies a local file to the remote host at the specified path
// using cat over SSH. The file permissions on the remote side are set to
// the provided mode.
func (c *Client) CopyTo(ctx context.Context, localPath, remotePath string, mode os.FileMode) error {
	data, err := c.readFile(localPath)
	if err != nil {
		return fmt.Errorf("read local file %s: %w", localPath, err)
	}

	// Use cat to write the file content, then chmod to set permissions.
	cmd := fmt.Sprintf("cat > %s && chmod %o %s",
		ShellEscape(remotePath), mode, ShellEscape(remotePath))

	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
	defer func() { _ = session.Close() }()

	session.SetStdin(bytes.NewReader(data))

	var output bytes.Buffer
	session.SetStdout(&output)
	session.SetStderr(&output)

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

	if err := c.writeFile(localPath, []byte(output), 0o644); err != nil {
		return fmt.Errorf("write local file %s: %w", localPath, err)
	}

	return nil
}

// WaitForReady polls the SSH server until a connection can be established
// or the context is cancelled. This is used to wait for the guest VM's
// SSH server to come up after boot.
func (c *Client) WaitForReady(ctx context.Context) error {
	tracer := otel.Tracer("github.com/stacklok/go-microvm")
	ctx, span := tracer.Start(ctx, "microvm.SSHWaitReady",
		trace.WithAttributes(
			attribute.String("ssh.host", c.host),
			attribute.Int("ssh.port", int(c.port)),
			attribute.String("ssh.user", c.user),
		))
	defer span.End()

	slog.Info("waiting for SSH to become ready",
		"host", c.host,
		"port", c.port,
		"user", c.user,
	)

	ticker := time.NewTicker(sshWaitPollInterval)
	defer ticker.Stop()

	probeCount := 0
	for {
		select {
		case <-ctx.Done():
			err := fmt.Errorf("context cancelled waiting for SSH: %w", ctx.Err())
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
			return err
		case <-ticker.C:
			probeCount++
			if err := c.probe(ctx); err != nil {
				slog.Debug("SSH not ready yet", "error", err)
				span.AddEvent("ssh.probe_failed", trace.WithAttributes(
					attribute.Int("ssh.probe_count", probeCount),
					attribute.String("error", err.Error()),
				))
				continue
			}
			span.SetAttributes(attribute.Int("ssh.probes_total", probeCount))
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
	session, cleanup, err := c.createSession(ctx)
	if err != nil {
		return err
	}
	defer cleanup()
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
	keyData, err := c.readFile(c.keyPath)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", c.keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyData)
	if err != nil {
		return nil, fmt.Errorf("parse SSH key %s: %w", c.keyPath, err)
	}

	var hostKeyCallback ssh.HostKeyCallback
	if c.expectedHostKey != nil {
		hostKeyCallback = ssh.FixedHostKey(c.expectedHostKey)
	} else {
		//nolint:gosec // Backward compat when host key not available.
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	return &ssh.ClientConfig{
		User: c.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
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
