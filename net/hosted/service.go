// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hosted

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/stacklok/propolis/net/topology"
)

// Service describes an HTTP service to expose inside the virtual network.
// The service listens on the gateway IP (192.168.127.1) at the given port,
// making it reachable from the guest VM without opening a real host socket.
type Service struct {
	// Port is the TCP port to listen on inside the virtual network.
	Port uint16

	// Handler is the HTTP handler that serves requests.
	Handler http.Handler
}

// runningService tracks a started service for graceful shutdown.
type runningService struct {
	server   *http.Server
	listener net.Listener
}

// AddService registers an HTTP service to be started when the provider starts.
// It must be called before Start; calling it after Start panics.
func (p *Provider) AddService(svc Service) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.vn != nil {
		panic("hosted: AddService called after Start")
	}

	p.pendingServices = append(p.pendingServices, svc)
}

// startServices starts all pending services on the virtual network.
// It must be called with p.mu held and after p.vn is set.
func (p *Provider) startServices() error {
	for i, svc := range p.pendingServices {
		addr := fmt.Sprintf("%s:%d", topology.GatewayIP, svc.Port)
		ln, err := p.vn.Listen("tcp", addr)
		if err != nil {
			// Clean up already-started services and wait for their
			// goroutines to drain before returning the error.
			p.shutdownServices(p.runningServices)
			p.runningServices = nil
			p.vn = nil
			return fmt.Errorf("listen on %s for service %d: %w", addr, i, err)
		}

		srv := &http.Server{
			Handler: svc.Handler,
		}

		p.runningServices = append(p.runningServices, runningService{
			server:   srv,
			listener: ln,
		})

		p.wg.Add(1)
		go func(srv *http.Server, ln net.Listener) {
			defer p.wg.Done()
			if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
				slog.Debug("hosted service stopped", "error", err)
			}
		}(srv, ln)
	}

	return nil
}

// snapshotAndClearServices takes the running services under the lock and
// clears the slice so no other caller sees them. The returned snapshot can
// be shut down outside the lock.
func (p *Provider) snapshotAndClearServices() []runningService {
	services := p.runningServices
	p.runningServices = nil
	return services
}

// shutdownServices gracefully shuts down the given services. It does NOT
// require p.mu to be held and must NOT be called with it held, because
// Shutdown may block waiting for in-flight requests.
func (p *Provider) shutdownServices(services []runningService) {
	for _, rs := range services {
		ctx, cancel := context.WithTimeout(context.Background(), serviceShutdownTimeout)
		if err := rs.server.Shutdown(ctx); err != nil {
			slog.Debug("service shutdown error", "error", err)
		}
		cancel()
	}
}

const serviceShutdownTimeout = 5 * time.Second
