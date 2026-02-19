// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package libkrun

import (
	"context"
	"strconv"

	"github.com/stacklok/propolis/runner"
)

// processHandle wraps a runner.ProcessHandle as a hypervisor.VMHandle.
type processHandle struct {
	proc runner.ProcessHandle
}

// Stop gracefully shuts down the runner process.
func (h *processHandle) Stop(ctx context.Context) error { return h.proc.Stop(ctx) }

// IsAlive reports whether the runner process is still running.
func (h *processHandle) IsAlive() bool { return h.proc.IsAlive() }

// ID returns the runner process PID as a string.
func (h *processHandle) ID() string { return strconv.Itoa(h.proc.PID()) }
