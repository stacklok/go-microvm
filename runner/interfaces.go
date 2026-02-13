// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package runner

import "context"

// ProcessHandle abstracts a running process for testability.
type ProcessHandle interface {
	Stop(ctx context.Context) error
	IsAlive() bool
	PID() int
}

// Spawner abstracts subprocess creation for testability.
type Spawner interface {
	Spawn(ctx context.Context, cfg Config) (ProcessHandle, error)
}

// DefaultSpawner is the production Spawner that delegates to Spawn().
type DefaultSpawner struct{}

// Spawn starts the runner binary. It implements the Spawner interface.
func (DefaultSpawner) Spawn(ctx context.Context, cfg Config) (ProcessHandle, error) {
	return SpawnProcess(ctx, cfg)
}
