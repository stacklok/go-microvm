// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package hosted implements a [net.Provider] that runs the gvisor-tap-vsock
// VirtualNetwork in the caller's process rather than inside go-microvm-runner.
//
// This enables callers to access the VirtualNetwork directly — for example,
// to create in-process TCP listeners via gonet that are reachable from the
// guest VM without opening real host sockets.
//
// # Usage
//
//	p := hosted.NewProvider()
//	vm, err := microvm.Run(ctx, image,
//	    microvm.WithNetProvider(p),
//	    microvm.WithPorts(microvm.PortForward{Host: sshPort, Guest: 22}),
//	)
//	// p.VirtualNetwork() is now available for gonet listeners.
//
// # HTTP Services
//
// Use [Provider.AddService] to register HTTP handlers that listen inside the
// virtual network on the gateway IP (192.168.127.1). Services are started
// before the guest boots and are reachable from inside the VM.
//
//	p := hosted.NewProvider()
//	p.AddService(hosted.Service{Port: 4483, Handler: myHandler})
//	vm, err := microvm.Run(ctx, image, microvm.WithNetProvider(p))
//	// Guest can reach http://192.168.127.1:4483/
//
// The provider exposes a Unix socket that go-microvm-runner connects to. Frames
// are bridged between the runner connection and the VirtualNetwork's QEMU
// transport. When firewall rules are configured, a [firewall.Relay] is
// inserted to filter traffic.
package hosted
