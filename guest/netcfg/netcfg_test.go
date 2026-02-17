// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netcfg

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stacklok/propolis/net/topology"
)

func TestConfigureRequiresRoot(t *testing.T) {
	t.Parallel()
	if os.Getuid() == 0 {
		t.Skip("test must run as non-root")
	}
	err := Configure(slog.Default())
	assert.Error(t, err)
}

func TestTopologyConstants(t *testing.T) {
	t.Parallel()
	// Verify the topology constants are what we expect.
	assert.Equal(t, "192.168.127.2", topology.GuestIP)
	assert.Equal(t, "192.168.127.1", topology.GatewayIP)
	assert.Equal(t, "192.168.127.0/24", topology.Subnet)
}
