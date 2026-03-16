// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package netcfg configures guest networking inside a microVM. It brings up
// eth0 with the guest IP from the go-microvm network topology, adds a default
// route via the gateway, and writes /etc/resolv.conf to point at the
// gateway's DNS service.
package netcfg
