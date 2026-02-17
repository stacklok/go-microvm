// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package mount provides essential filesystem mounts and virtiofs workspace
// mounts for guest VMs running under libkrun. It handles the minimal set of
// pseudo-filesystems (/proc, /sys, /dev, /dev/pts, /tmp, /run) required for
// a functioning Linux userspace, plus optional virtiofs shares for host
// directory access.
package mount
