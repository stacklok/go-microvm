// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hosted

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/stacklok/go-microvm/hypervisor"
)

func defaultListener(logDir string) (net.Listener, hypervisor.NetEndpoint, func(), error) {
	sockPath := filepath.Join(logDir, socketName)
	if err := os.Remove(sockPath); err != nil && !os.IsNotExist(err) {
		return nil, hypervisor.NetEndpoint{}, nil, fmt.Errorf("remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, hypervisor.NetEndpoint{}, nil, fmt.Errorf("listen on unix socket: %w", err)
	}

	cleanup := func() {
		_ = os.Remove(sockPath)
	}
	endpoint := hypervisor.NetEndpoint{Type: hypervisor.NetEndpointUnixSocket, Path: sockPath}
	return listener, endpoint, cleanup, nil
}
