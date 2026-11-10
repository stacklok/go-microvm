// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hosted

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/linuxkit/virtsock/pkg/hvsock"

	"github.com/stacklok/go-microvm/hypervisor"
)

const hvSocketNetPort = 2048

func defaultListener(logDir string) (net.Listener, hypervisor.NetEndpoint, func(), error) {
	serviceID, err := hvsock.GUIDFromString(fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", hvSocketNetPort))
	if err != nil {
		return nil, hypervisor.NetEndpoint{}, nil, fmt.Errorf("create Hyper-V service ID: %w", err)
	}

	listener, err := hvsock.Listen(hvsock.Addr{VMID: hvsock.GUIDWildcard, ServiceID: serviceID})
	if err == nil {
		endpoint := hypervisor.NetEndpoint{Type: hypervisor.NetEndpointHVSocket, Path: serviceID.String()}
		return listener, endpoint, func() {}, nil
	}

	sockPath := filepath.Join(logDir, socketName)
	if removeErr := os.Remove(sockPath); removeErr != nil && !os.IsNotExist(removeErr) {
		return nil, hypervisor.NetEndpoint{}, nil, fmt.Errorf("remove stale fallback socket: %w", removeErr)
	}
	listener, err = net.Listen("unix", sockPath)
	if err != nil {
		return nil, hypervisor.NetEndpoint{}, nil, fmt.Errorf("listen on fallback unix socket: %w", err)
	}
	cleanup := func() {
		_ = os.Remove(sockPath)
	}
	endpoint := hypervisor.NetEndpoint{Type: hypervisor.NetEndpointUnixSocket, Path: sockPath}
	return listener, endpoint, cleanup, nil
}
