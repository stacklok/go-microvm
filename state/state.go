// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package state provides VM state persistence with file-based locking.
//
// State is persisted as a JSON file alongside a lock file. The [Manager]
// provides atomic load-and-lock semantics via [LockedState], ensuring that
// only one process can modify a VM's state at a time. Saves are atomic
// (write to temp file, then rename).
package state

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

const (
	// stateVersion is the current state file format version.
	stateVersion = 1

	// stateFileName is the name of the state JSON file within the data directory.
	// Named "go-microvm-state.json" to avoid collision with the caller's own
	// state file (e.g. toolhive-appliance's "state.json") when both share
	// the same dataDir.
	stateFileName = "go-microvm-state.json"

	// lockFileName is the name of the lock file within the data directory.
	lockFileName = "go-microvm-state.lock"

	// retryInterval is the interval between lock acquisition retries.
	retryInterval = 500 * time.Millisecond
)

// State represents persisted VM state.
type State struct {
	// Version is the state file format version.
	Version int `json:"version"`

	// Active indicates whether the VM is currently running.
	Active bool `json:"active"`

	// Name is the VM name.
	Name string `json:"name"`

	// Image is the OCI image reference used to create the VM.
	Image string `json:"image"`

	// CPUs is the number of virtual CPUs assigned to the VM.
	CPUs uint32 `json:"cpus"`

	// MemoryMB is the amount of RAM in MiB assigned to the VM.
	MemoryMB uint32 `json:"memory_mb"`

	// PID is the process ID of the VM runner, or 0 if not running.
	PID int `json:"pid,omitempty"`

	// CreatedAt is the time the VM state was first created.
	CreatedAt time.Time `json:"created_at"`
}

// Manager handles VM state persistence with file locking.
type Manager struct {
	dataDir string
}

// LockedState holds a state with an exclusive file lock. The lock is held
// until [LockedState.Release] is called. Callers should use defer to ensure
// the lock is always released.
type LockedState struct {
	State *State
	lock  *flock.Flock
	path  string
}

// NewManager creates a new state Manager that stores state files in the
// given data directory.
func NewManager(dataDir string) *Manager {
	return &Manager{dataDir: dataDir}
}

// statePath returns the path to the state JSON file.
func (m *Manager) statePath() string {
	return filepath.Join(m.dataDir, stateFileName)
}

// lockPath returns the path to the lock file.
func (m *Manager) lockPath() string {
	return filepath.Join(m.dataDir, lockFileName)
}

// LoadAndLock loads the current state and acquires an exclusive file lock.
// The returned [LockedState] must be released by calling [LockedState.Release]
// when the caller is done reading or modifying the state.
//
// If no state file exists, a new default State is returned (still locked).
func (m *Manager) LoadAndLock(ctx context.Context) (*LockedState, error) {
	if err := os.MkdirAll(m.dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create state dir: %w", err)
	}

	fl := flock.New(m.lockPath())

	locked, err := fl.TryLockContext(ctx, retryInterval)
	if err != nil {
		return nil, fmt.Errorf("acquire state lock: %w", err)
	}
	if !locked {
		return nil, fmt.Errorf("failed to acquire state lock at %s", m.lockPath())
	}

	state, err := m.loadState()
	if err != nil {
		_ = fl.Unlock()
		return nil, err
	}

	return &LockedState{
		State: state,
		lock:  fl,
		path:  m.statePath(),
	}, nil
}

// LoadAndLockWithRetry attempts to load and lock state, retrying with the
// given interval until the context deadline is reached or the lock is
// acquired.
func (m *Manager) LoadAndLockWithRetry(ctx context.Context, timeout time.Duration) (*LockedState, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		ls, err := m.LoadAndLock(ctx)
		if err == nil {
			return ls, nil
		}

		// If the context is done, return the error.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("timeout waiting for state lock after %s: %w", timeout, err)
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for state lock: %w", ctx.Err())
		case <-time.After(retryInterval):
			// Retry.
		}
	}
}

// Load reads the current state without locking. This is useful for
// read-only access where consistency with subsequent writes is not needed.
func (m *Manager) Load() (*State, error) {
	return m.loadState()
}

// loadState reads and parses the state file. If the file does not exist,
// it returns a new default State.
func (m *Manager) loadState() (*State, error) {
	data, err := os.ReadFile(m.statePath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &State{
				Version:   stateVersion,
				CreatedAt: time.Now(),
			}, nil
		}
		return nil, fmt.Errorf("read state file: %w", err)
	}

	var state State
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse state file: %w", err)
	}

	return &state, nil
}

// Save atomically writes the state to disk. The state is first written to
// a temporary file, then renamed to the final path. This ensures that a
// crash during write does not corrupt the state file.
//
// Save must only be called while the lock is held.
func (ls *LockedState) Save() error {
	ls.State.Version = stateVersion

	data, err := json.MarshalIndent(ls.State, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	// Write to a temporary file in the same directory (for atomic rename).
	dir := filepath.Dir(ls.path)

	tmp, err := os.CreateTemp(dir, "state-*.json.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmp.Name()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("write temp state file: %w", err)
	}

	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close temp state file: %w", err)
	}

	// Atomic rename.
	if err := os.Rename(tmpPath, ls.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename state file: %w", err)
	}

	return nil
}

// Release releases the exclusive file lock. It is safe to call multiple
// times; subsequent calls are no-ops.
func (ls *LockedState) Release() {
	if ls.lock != nil {
		_ = ls.lock.Unlock()
	}
}

// Remove deletes the state and lock files from disk. The lock must be held
// when calling this method.
func (ls *LockedState) Remove() error {
	if err := os.Remove(ls.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove state file: %w", err)
	}
	return nil
}
