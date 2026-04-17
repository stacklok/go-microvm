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

	"github.com/stacklok/go-microvm/net/topology"
)

// Default HTTP server timeouts for hosted services. These protect the
// host process from a misbehaving or hostile guest that opens
// connections but stalls the request — classic Slowloris / slow-body
// patterns — exhausting goroutines and file descriptors in the caller's
// process. Callers can override any of these per-Service if they ship a
// streaming handler that legitimately takes longer than the default.
const (
	defaultReadHeaderTimeout = 10 * time.Second
	defaultReadTimeout       = 30 * time.Second
	defaultWriteTimeout      = 30 * time.Second
	defaultIdleTimeout       = 60 * time.Second
)

// Service describes an HTTP service to expose inside the virtual network.
//
// Services always bind to the gateway IP ([topology.GatewayIP], 192.168.127.1)
// because that is the only host-side address reachable from the guest. Callers
// that need to listen on a different address can use
// [Provider.VirtualNetwork].Listen directly.
type Service struct {
	// Port is the TCP port to listen on at the gateway IP inside the
	// virtual network.
	Port uint16

	// Handler is the HTTP handler that serves requests.
	Handler http.Handler

	// ReadHeaderTimeout bounds the time the server will wait to finish
	// reading request headers. Zero uses defaultReadHeaderTimeout.
	ReadHeaderTimeout time.Duration

	// ReadTimeout bounds the total time reading a request including
	// the body. Zero uses defaultReadTimeout.
	ReadTimeout time.Duration

	// WriteTimeout bounds the total time writing the response. Zero
	// uses defaultWriteTimeout.
	WriteTimeout time.Duration

	// IdleTimeout bounds the time a keep-alive connection may remain
	// idle between requests. Zero uses defaultIdleTimeout.
	IdleTimeout time.Duration
}

// timeoutOrDefault returns user if set, else the fallback default.
func timeoutOrDefault(user, fallback time.Duration) time.Duration {
	if user > 0 {
		return user
	}
	return fallback
}

// newHTTPServer constructs an *http.Server for the given Service with
// Slowloris-bounding timeouts applied. Zero-valued timeout fields on
// svc fall back to defaults.
func newHTTPServer(svc Service) *http.Server {
	return &http.Server{
		Handler:           svc.Handler,
		ReadHeaderTimeout: timeoutOrDefault(svc.ReadHeaderTimeout, defaultReadHeaderTimeout),
		ReadTimeout:       timeoutOrDefault(svc.ReadTimeout, defaultReadTimeout),
		WriteTimeout:      timeoutOrDefault(svc.WriteTimeout, defaultWriteTimeout),
		IdleTimeout:       timeoutOrDefault(svc.IdleTimeout, defaultIdleTimeout),
	}
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

		srv := newHTTPServer(svc)

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
