// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netcfg

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/go-microvm/net/topology"
)

func TestBridgeStreamToPacket_ARPRoundTrip(t *testing.T) {
	t.Parallel()

	vn, err := virtualnetwork.New(&types.Configuration{
		Subnet:            topology.Subnet,
		GatewayIP:         topology.GatewayIP,
		GatewayMacAddress: topology.GatewayMAC,
		MTU:               topology.MTU,
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bridgeStream, networkStream := net.Pipe()
	bridgeTap, testTap := net.Pipe()
	t.Cleanup(func() {
		_ = bridgeStream.Close()
		_ = networkStream.Close()
		_ = bridgeTap.Close()
		_ = testTap.Close()
	})
	go func() { _ = vn.AcceptQemu(ctx, networkStream) }()
	go func() { _ = BridgeStreamToPacket(ctx, bridgeStream, bridgeTap) }()

	request := arpRequest(t)
	require.NoError(t, testTap.SetDeadline(time.Now().Add(2*time.Second)))
	_, err = testTap.Write(request)
	require.NoError(t, err)

	reply := make([]byte, maxEthernetFrameSize)
	size, err := testTap.Read(reply)
	require.NoError(t, err)
	reply = reply[:size]
	require.GreaterOrEqual(t, len(reply), 42)
	assert.Equal(t, request[6:12], reply[0:6])
	assert.Equal(t, uint16(2), binary.BigEndian.Uint16(reply[20:22]))
	assert.Equal(t, net.ParseIP(topology.GatewayIP).To4(), net.IP(reply[28:32]))
}

func arpRequest(t *testing.T) []byte {
	t.Helper()
	guestMAC, err := net.ParseMAC("5a:94:ef:e4:0c:ee")
	require.NoError(t, err)
	gatewayIP := net.ParseIP(topology.GatewayIP).To4()
	guestIP := net.ParseIP(topology.GuestIP).To4()
	require.NotNil(t, gatewayIP)
	require.NotNil(t, guestIP)

	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], guestMAC)
	binary.BigEndian.PutUint16(frame[12:14], 0x0806)
	binary.BigEndian.PutUint16(frame[14:16], 1)
	binary.BigEndian.PutUint16(frame[16:18], 0x0800)
	frame[18] = 6
	frame[19] = 4
	binary.BigEndian.PutUint16(frame[20:22], 1)
	copy(frame[22:28], guestMAC)
	copy(frame[28:32], guestIP)
	copy(frame[38:42], gatewayIP)
	return frame
}
