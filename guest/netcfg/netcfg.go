// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package netcfg

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/vishvananda/netlink"

	"github.com/stacklok/propolis/net/topology"
)

// Configure brings up the guest network interface with the standard propolis
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

	if err := netlink.AddrAdd(link, addr); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("adding address to eth0: %w", err)
		}
		logger.Debug("address already configured on eth0, skipping")
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bringing up eth0: %w", err)
	}

	route := &netlink.Route{
		Gw: net.ParseIP(topology.GatewayIP),
	}
	if err := netlink.RouteAdd(route); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			return fmt.Errorf("adding default route: %w", err)
		}
		logger.Debug("default route already configured, skipping")
	}

	if err := os.WriteFile("/etc/resolv.conf", []byte("nameserver "+topology.GatewayIP+"\n"), 0o644); err != nil {
		return fmt.Errorf("writing resolv.conf: %w", err)
	}

	return nil
}
