// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package logbridge redirects third-party loggers (logrus) through slog so
// that all log output flows through the caller's slog configuration.
//
// The primary consumer is gvisor-tap-vsock which uses logrus internally. Without
// the bridge, its output goes directly to stderr and pollutes interactive
// terminal sessions.
package logbridge
