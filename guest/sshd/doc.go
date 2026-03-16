// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package sshd provides an embedded SSH server for guest VMs. It supports
// public-key authentication, command execution with PTY support, environment
// variable injection, signal forwarding, and window-change handling. The
// server is designed to run inside a microVM as the primary remote access
// mechanism, paired with the host-side ssh.Client from the go-microvm/ssh package.
package sshd
