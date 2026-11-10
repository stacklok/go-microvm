// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hosted

import (
	"fmt"
	"github.com/linuxkit/virtsock/pkg/hvsock"
	"net"

	"github.com/stacklok/go-microvm/hypervisor"
)

const (
	hvSocketNetPortBase  = 2048
	hvSocketNetPortCount = 64
)

func defaultListener(_ string) (net.Listener, hypervisor.NetEndpoint, func(), error) {
	var lastErr error
	for offset := range uint32(hvSocketNetPortCount) {
		port := uint32(hvSocketNetPortBase) + offset
		serviceID, err := hvsock.GUIDFromString(fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", port))
		if err != nil {
			return nil, hypervisor.NetEndpoint{}, nil, fmt.Errorf("create Hyper-V service ID: %w", err)
		}
		listener, err := hvsock.Listen(hvsock.Addr{VMID: hvsock.GUIDWildcard, ServiceID: serviceID})
		if err == nil {
			endpoint := hypervisor.NetEndpoint{Type: hypervisor.NetEndpointHVSocket, Path: serviceID.String()}
			return listener, endpoint, func() {}, nil
		}
		lastErr = err
	}
	return nil, hypervisor.NetEndpoint{}, nil, fmt.Errorf(
		"listen on Hyper-V socket ports %d-%d: %w",
		hvSocketNetPortBase,
		hvSocketNetPortBase+hvSocketNetPortCount-1,
		lastErr,
	)
}
