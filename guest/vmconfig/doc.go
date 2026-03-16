// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package vmconfig reads the VM configuration file written by the host into
// the rootfs before boot. Guest init binaries use this to apply host-side
// configuration (e.g. /tmp size) before the SSH server starts.
package vmconfig
