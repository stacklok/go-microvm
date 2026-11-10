// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hyperv

import (
	"context"

	"github.com/stacklok/go-microvm/hypervisor"
)

type vmHandle struct {
	handle Handle
}

var _ hypervisor.VMHandle = (*vmHandle)(nil)

func (h *vmHandle) Stop(ctx context.Context) error { return h.handle.Stop(ctx) }
func (h *vmHandle) IsAlive() bool                  { return h.handle.IsAlive() }
func (h *vmHandle) ID() string                     { return h.handle.ID() }
