// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package boot orchestrates the guest VM boot sequence: essential mounts,
// networking, workspace mount, kernel hardening, environment loading, SSH
// key parsing, capability dropping, and SSH server start. It uses functional
// options to replace the hardcoded values found in consumer-specific init
// processes, making it reusable across different guest VM configurations.
package boot
