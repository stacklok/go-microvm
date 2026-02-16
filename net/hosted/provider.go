// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hosted

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/containers/gvisor-tap-vsock/pkg/types"
	"github.com/containers/gvisor-tap-vsock/pkg/virtualnetwork"

	propnet "github.com/stacklok/propolis/net"
	"github.com/stacklok/propolis/net/firewall"
	"github.com/stacklok/propolis/net/topology"
)

const socketName = "hosted-net.sock"

// Provider runs a gvisor-tap-vsock VirtualNetwork in the caller's process
// and exposes a Unix socket for propolis-runner to connect to.
type Provider struct {
	mu              sync.Mutex
	vn              *virtualnetwork.VirtualNetwork
	listener        net.Listener
	sockPath        string
	relay           *firewall.Relay
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	pendingServices []Service
	runningServices []runningService
}

// NewProvider creates a new hosted network provider.
func NewProvider() *Provider {
	return &Provider{}
}

// Start launches the virtual network and begins listening on a Unix socket.
// It satisfies the [net.Provider] interface.
func (p *Provider) Start(ctx context.Context, cfg propnet.Config) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.vn != nil {
		return fmt.Errorf("provider already started")
	}

	// Build port forward map: "127.0.0.1:<host>" -> "<guestIP>:<guest>"
	forwards := make(map[string]string, len(cfg.Forwards))
	for _, pf := range cfg.Forwards {
		hostAddr := fmt.Sprintf("127.0.0.1:%d", pf.Host)
		guestAddr := fmt.Sprintf("%s:%d", topology.GuestIP, pf.Guest)
		forwards[hostAddr] = guestAddr
	}

	// Create the virtual network stack.
	vn, err := virtualnetwork.New(&types.Configuration{
		Subnet:            topology.Subnet,
		GatewayIP:         topology.GatewayIP,
		GatewayMacAddress: topology.GatewayMAC,
		MTU:               topology.MTU,
		Forwards:          forwards,
	})
	if err != nil {
		return fmt.Errorf("create virtual network: %w", err)
	}
	p.vn = vn

	// Start any registered services on the virtual network.
	if err := p.startServices(); err != nil {
		return fmt.Errorf("start services: %w", err)
	}

	// Prepare the Unix socket path.
	p.sockPath = filepath.Join(cfg.LogDir, socketName)

	// Remove stale socket if present.
	if err := os.Remove(p.sockPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", p.sockPath)
	if err != nil {
		return fmt.Errorf("listen on unix socket: %w", err)
	}
	p.listener = listener

	// Set up optional firewall relay.
	if len(cfg.FirewallRules) > 0 {
		filter := firewall.NewFilter(cfg.FirewallRules, cfg.FirewallDefaultAction)
		p.relay = firewall.NewRelay(filter)

		bgCtx, cancel := context.WithCancel(ctx)
		p.cancel = cancel
		filter.StartExpiry(bgCtx)
	} else {
		_, cancel := context.WithCancel(ctx)
		p.cancel = cancel
	}

	// Accept connections in the background.
	p.wg.Add(1)
	go p.acceptLoop()

	return nil
}

// SocketPath returns the path to the Unix socket for propolis-runner.
func (p *Provider) SocketPath() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sockPath
}

// Stop terminates the provider and cleans up resources.
func (p *Provider) Stop() {
	p.mu.Lock()
	services := p.snapshotAndClearServices()
	cancel := p.cancel
	listener := p.listener
	sockPath := p.sockPath
	p.mu.Unlock()

	// Shut down HTTP services outside the lock so Shutdown's blocking
	// does not prevent other callers from acquiring the mutex.
	p.shutdownServices(services)

	if cancel != nil {
		cancel()
	}

	if listener != nil {
		_ = listener.Close()
	}

	// Wait for the accept loop to finish.
	p.wg.Wait()

	// Clean up the socket file.
	if sockPath != "" {
		_ = os.Remove(sockPath)
	}
}

// VirtualNetwork returns the underlying gvisor-tap-vsock VirtualNetwork.
// Returns nil before Start is called.
func (p *Provider) VirtualNetwork() *virtualnetwork.VirtualNetwork {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.vn
}

// Relay returns the firewall relay, or nil if no firewall rules are configured.
func (p *Provider) Relay() *firewall.Relay {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.relay
}

// acceptLoop accepts connections from propolis-runner and bridges them
// to the VirtualNetwork.
func (p *Provider) acceptLoop() {
	defer p.wg.Done()

	for {
		conn, err := p.listener.Accept()
		if err != nil {
			// Listener closed during Stop — expected.
			return
		}

		p.wg.Add(1)
		go p.handleConn(conn)
	}
}

// handleConn bridges a single runner connection to the VirtualNetwork.
func (p *Provider) handleConn(runnerConn net.Conn) {
	defer p.wg.Done()

	p.mu.Lock()
	vn := p.vn
	relay := p.relay
	p.mu.Unlock()

	if relay != nil {
		// With firewall: create an in-memory pipe. The relay sits between
		// the runner connection and one end of the pipe; the other end
		// is passed to AcceptQemu.
		vnConn, relayConn := net.Pipe()

		// Start the relay between runner and the pipe end.
		go func() {
			if err := relay.Run(context.Background(), runnerConn, relayConn); err != nil {
				slog.Debug("relay ended", "error", err)
			}
		}()

		// Bridge pipe's other end to the VirtualNetwork.
		if err := vn.AcceptQemu(context.Background(), vnConn); err != nil {
			slog.Debug("AcceptQemu ended", "error", err)
		}
	} else {
		// Without firewall: direct bridge.
		if err := vn.AcceptQemu(context.Background(), runnerConn); err != nil {
			slog.Debug("AcceptQemu ended", "error", err)
		}
	}
}
