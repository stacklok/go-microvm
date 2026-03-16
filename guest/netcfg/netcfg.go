// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netcfg

import (
	"fmt"
	"log/slog"
	"net"
	"os"

	"github.com/vishvananda/netlink"

	"github.com/stacklok/go-microvm/net/topology"
)

// Configure brings up the guest network interface with the standard go-microvm
// topology: eth0 gets the guest IP (192.168.127.2/24), a default route via
// the gateway (192.168.127.1), and /etc/resolv.conf pointing at the gateway.
func Configure(logger *slog.Logger) error {
	logger.Info("configuring guest network",
		"guestIP", topology.GuestIP,
		"gateway", topology.GatewayIP,
	)

	link, err := netlink.LinkByName("eth0")
	if err != nil {
		return fmt.Errorf("finding eth0: %w", err)
	}

	addr, err := netlink.ParseAddr(topology.GuestIP + "/24")
	if err != nil {
		return fmt.Errorf("parsing guest address: %w", err)
	}

	if err := netlink.AddrReplace(link, addr); err != nil {
		return fmt.Errorf("configuring address on eth0: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing up eth0: %w", err)
	}

	route := &netlink.Route{
		Gw: net.ParseIP(topology.GatewayIP),
	}
	if err := netlink.RouteReplace(route); err != nil {
		return fmt.Errorf("configuring default route: %w", err)
	}

	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver "+topology.GatewayIP+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing resolv.conf: %w", err)
	}

	return nil
}
