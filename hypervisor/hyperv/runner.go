// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hyperv

import "context"

// Runner creates and starts an HCS compute system.
type Runner interface {
	CreateAndStart(ctx context.Context, id string, doc *ComputeSystem) (Handle, error)
}

// Handle controls an HCS compute system.
type Handle interface {
	Stop(ctx context.Context) error
	IsAlive() bool
	ID() string
}
