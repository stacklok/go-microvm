// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package ssh provides SSH key generation and client utilities for
// communicating with microVMs.
//
// The package generates ECDSA P-256 key pairs for authentication and
// provides a high-level [Client] that wraps the underlying SSH connection
// with convenience methods for running commands, copying files, and
// waiting for the guest to become ready.
package ssh
