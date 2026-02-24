// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sshd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// maxConcurrentConns is the maximum number of concurrent SSH connections.
	maxConcurrentConns = 4

	// maxChannelsPerConn is the maximum number of channels per connection.
	maxChannelsPerConn = 10

	// handshakeTimeout is the deadline for the SSH handshake to complete.
	handshakeTimeout = 30 * time.Second
)

// Config holds the configuration for the embedded SSH server.
type Config struct {
	// Port is the TCP port to listen on. Use 0 to let the OS assign a
	// free port.
	Port int

	// AuthorizedKeys is the list of public keys permitted to connect.
	AuthorizedKeys []ssh.PublicKey

	// Env is the base environment passed to every spawned command.
	Env []string

	// DefaultUID is the numeric user ID for spawned processes.
	DefaultUID uint32

	// DefaultGID is the numeric group ID for spawned processes.
	DefaultGID uint32

	// DefaultUser is the username reported to the shell.
	DefaultUser string

	// DefaultHome is the home directory for spawned processes.
	DefaultHome string

	// DefaultShell is the login shell binary (e.g. "/bin/sh").
	DefaultShell string

	// DefaultWorkDir is the working directory for spawned commands. If
	// empty or the directory does not exist, DefaultHome is used instead.
	DefaultWorkDir string

	// AgentForwarding enables SSH agent forwarding support. When true,
	// the server accepts auth-agent-req@openssh.com requests and creates
	// per-session agent sockets.
	AgentForwarding bool

	// HostKey is an optional pre-generated host key signer. When non-nil,
	// the server uses this key instead of generating an ephemeral one.
	// This enables host key pinning by the client.
	HostKey ssh.Signer

	// Logger is the structured logger. If nil, slog.Default() is used.
	Logger *slog.Logger
}

// Server is an embedded SSH server designed to run inside a guest VM.
type Server struct {
	cfg        Config
	sshCfg     *ssh.ServerConfig
	listener   net.Listener
	wg         sync.WaitGroup
	quit       chan struct{}
	logger     *slog.Logger
	agentFwdMu sync.Mutex
	agentFwd   map[*ssh.ServerConn]bool
}

// New creates a new Server with an ephemeral ECDSA P-256 host key. It
// configures public-key authentication against the supplied authorized
// keys and allows at most one authentication attempt per connection.
func New(cfg Config) (*Server, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	sshCfg := &ssh.ServerConfig{
		MaxAuthTries: 1,
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			for _, ak := range cfg.AuthorizedKeys {
				if ak.Type() == key.Type() &&
					subtle.ConstantTimeCompare(ak.Marshal(), key.Marshal()) == 1 {
					logger.Info("public key accepted",
						"user", conn.User(),
						"remote", conn.RemoteAddr(),
					)
					return &ssh.Permissions{}, nil
				}
			}
			logger.Warn("public key rejected",
				"user", conn.User(),
				"remote", conn.RemoteAddr(),
			)
			return nil, fmt.Errorf("unknown public key for %s", conn.User())
		},
	}

	if cfg.HostKey != nil {
		// Use the injected host key (enables client-side pinning).
		sshCfg.AddHostKey(cfg.HostKey)
	} else {
		// Generate an ephemeral ECDSA P-256 host key.
		hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate host key: %w", err)
		}

		signer, err := ssh.NewSignerFromKey(hostKey)
		if err != nil {
			return nil, fmt.Errorf("create host key signer: %w", err)
		}

		sshCfg.AddHostKey(signer)
	}

	return &Server{
		cfg:      cfg,
		sshCfg:   sshCfg,
		quit:     make(chan struct{}),
		logger:   logger,
		agentFwd: make(map[*ssh.ServerConn]bool),
	}, nil
}

// Port returns the actual port the server is listening on. This is
// especially useful when the server was started with port 0.
func (s *Server) Port() int {
	if s.listener == nil {
		return s.cfg.Port
	}
	return s.listener.Addr().(*net.TCPAddr).Port
}

// ListenAndServe opens a TCP listener on the configured port and serves
// SSH connections until Close is called.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.cfg.Port))
	if err != nil {
		return fmt.Errorf("listen on port %d: %w", s.cfg.Port, err)
	}

	s.logger.Info("SSH server listening", "addr", ln.Addr().String())
	return s.Serve(ln)
}

// Serve accepts connections on the provided listener. It limits
// concurrent connections to maxConcurrentConns via a semaphore.
func (s *Server) Serve(ln net.Listener) error {
	s.listener = ln
	sem := make(chan struct{}, maxConcurrentConns)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.quit:
				return nil
			default:
				s.logger.Error("accept failed", "error", err)
				continue
			}
		}

		sem <- struct{}{}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer func() { <-sem }()
			s.handleConnection(conn)
		}()
	}
}

// Close gracefully shuts down the server by closing the listener and
// waiting for active connections to finish.
func (s *Server) Close() {
	close(s.quit)
	if s.listener != nil {
		_ = s.listener.Close()
	}
	s.wg.Wait()
}

// handleConnection performs the SSH handshake and dispatches session
// channels. It enforces a handshake deadline and limits the number of
// channels per connection.
func (s *Server) handleConnection(netConn net.Conn) {
	defer func() { _ = netConn.Close() }()

	// Enforce a handshake deadline.
	if err := netConn.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		s.logger.Error("set handshake deadline", "error", err)
		return
	}

	srvConn, chans, reqs, err := ssh.NewServerConn(netConn, s.sshCfg)
	if err != nil {
		s.logger.Debug("SSH handshake failed",
			"remote", netConn.RemoteAddr(),
			"error", err,
		)
		return
	}
	defer func() { _ = srvConn.Close() }()
	defer s.setAgentForwarding(srvConn, false)

	// Clear the deadline after a successful handshake.
	if err := netConn.SetDeadline(time.Time{}); err != nil {
		s.logger.Error("clear deadline", "error", err)
		return
	}

	s.logger.Info("SSH connection established",
		"user", srvConn.User(),
		"remote", srvConn.RemoteAddr(),
	)

	// Handle global requests (agent forwarding, keepalive, etc.).
	go s.handleGlobalRequests(reqs, srvConn)

	channelCount := 0
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			s.logger.Warn("rejecting non-session channel",
				"type", newCh.ChannelType(),
			)
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}

		channelCount++
		if channelCount > maxChannelsPerConn {
			s.logger.Warn("too many channels, rejecting",
				"count", channelCount,
			)
			_ = newCh.Reject(ssh.ResourceShortage, "too many channels")
			continue
		}

		ch, requests, err := newCh.Accept()
		if err != nil {
			s.logger.Error("accept channel", "error", err)
			continue
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSession(ch, requests, srvConn)
		}()
	}
}

// handleGlobalRequests processes connection-level SSH requests.
// It handles agent forwarding requests when enabled and discards
// all other global requests.
func (s *Server) handleGlobalRequests(reqs <-chan *ssh.Request, conn *ssh.ServerConn) {
	for req := range reqs {
		switch req.Type {
		case "auth-agent-req@openssh.com":
			if s.cfg.AgentForwarding {
				s.setAgentForwarding(conn, true)
				s.logger.Info("agent forwarding enabled",
					"remote", conn.RemoteAddr(),
				)
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			} else {
				s.logger.Debug("agent forwarding rejected (disabled)",
					"remote", conn.RemoteAddr(),
				)
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
}

// setAgentForwarding records or clears the agent-forwarding state for
// the given connection.
func (s *Server) setAgentForwarding(conn *ssh.ServerConn, enabled bool) {
	s.agentFwdMu.Lock()
	defer s.agentFwdMu.Unlock()
	if enabled {
		s.agentFwd[conn] = true
	} else {
		delete(s.agentFwd, conn)
	}
}

// isAgentForwarding reports whether agent forwarding has been enabled
// for the given connection.
func (s *Server) isAgentForwarding(conn *ssh.ServerConn) bool {
	s.agentFwdMu.Lock()
	defer s.agentFwdMu.Unlock()
	return s.agentFwd[conn]
}
