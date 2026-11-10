// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hyperv

import (
	"fmt"
	"net"

	"github.com/linuxkit/virtsock/pkg/hvsock"
)

func defaultVsockListener(port uint32) (net.Listener, error) {
	serviceID, err := hvsock.GUIDFromString(VsockPortToServiceGUID(port))
	if err != nil {
		return nil, fmt.Errorf("parse Hyper-V service GUID for port %d: %w", port, err)
	}
	return hvsock.Listen(hvsock.Addr{VMID: hvsock.GUIDWildcard, ServiceID: serviceID})
}
