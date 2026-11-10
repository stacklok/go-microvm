// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hyperv

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
)

const (
	errVmcomputeOperationPending      syscall.Errno = 0xC0370103
	errVmcomputeOperationInvalidState syscall.Errno = 0xC0370105
	errVmcomputeUnexpectedExit        syscall.Errno = 0xC0370106
	errComputeSystemDoesNotExist      syscall.Errno = 0xC037010E
	errVmcomputeAlreadyStopped        syscall.Errno = 0xC0370110

	notificationSystemExited          uint32 = 0x00000001
	notificationSystemCreateCompleted uint32 = 0x00000002
	notificationSystemStartCompleted  uint32 = 0x00000003
	notificationSystemShutdownFailed  uint32 = 0x0000000A
	notificationServiceDisconnect     uint32 = 0x01000000

	gracefulShutdownTimeout = 10 * time.Second
)

func isAlreadyStoppedError(err error) bool {
	return errors.Is(err, errVmcomputeAlreadyStopped) ||
		errors.Is(err, errComputeSystemDoesNotExist) ||
		errors.Is(err, errVmcomputeUnexpectedExit)
}

type notificationTracker struct {
	mu              sync.Mutex
	signal          chan struct{}
	completed       map[uint32]error
	exited          bool
	exitErr         error
	shutdownFailed  bool
	shutdownFailErr error
	disconnected    bool
}

func newNotificationTracker() *notificationTracker {
	return &notificationTracker{
		signal:    make(chan struct{}),
		completed: make(map[uint32]error),
	}
}

func (t *notificationTracker) notify(typeID uint32, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch typeID {
	case notificationServiceDisconnect:
		t.disconnected = true
	case notificationSystemExited:
		t.exited = true
		t.exitErr = err
	case notificationSystemShutdownFailed:
		t.shutdownFailed = true
		t.shutdownFailErr = err
	default:
		t.completed[typeID] = err
	}
	close(t.signal)
	t.signal = make(chan struct{})
}

func (t *notificationTracker) waitFor(ctx context.Context, expected uint32) error {
	for {
		t.mu.Lock()
		if t.disconnected {
			t.mu.Unlock()
			return fmt.Errorf("vmcompute service disconnected")
		}
		if expected == notificationSystemExited {
			if t.exited {
				err := t.exitErr
				t.mu.Unlock()
				if isAlreadyStoppedError(err) {
					return nil
				}
				return err
			}
		} else {
			if err, ok := t.completed[expected]; ok {
				t.mu.Unlock()
				return err
			}
			if t.exited {
				err := t.exitErr
				t.mu.Unlock()
				if err != nil {
					return err
				}
				return fmt.Errorf("compute system exited before operation completed")
			}
		}
		sig := t.signal
		t.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sig:
		}
	}
}

func (t *notificationTracker) waitForShutdown(ctx context.Context) error {
	for {
		t.mu.Lock()
		if t.disconnected {
			t.mu.Unlock()
			return fmt.Errorf("vmcompute service disconnected")
		}
		if t.exited {
			err := t.exitErr
			t.mu.Unlock()
			if isAlreadyStoppedError(err) {
				return nil
			}
			return err
		}
		if t.shutdownFailed {
			err := t.shutdownFailErr
			t.mu.Unlock()
			if err != nil {
				return fmt.Errorf("compute system graceful shutdown failed: %w", err)
			}
			return errors.New("compute system graceful shutdown failed")
		}
		sig := t.signal
		t.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-sig:
		}
	}
}

func runStopLifecycle(
	ctx context.Context,
	tracker *notificationTracker,
	shutdownFn func() error,
	terminateFn func() error,
	closeFn func() error,
) error {
	var stopErr error
	shutdownErr := shutdownFn()
	switch {
	case isAlreadyStoppedError(shutdownErr):
		stopErr = nil
	case shutdownErr == nil || errors.Is(shutdownErr, errVmcomputeOperationPending):
		shutdownCtx, cancel := context.WithTimeout(ctx, gracefulShutdownTimeout)
		stopErr = tracker.waitForShutdown(shutdownCtx)
		cancel()
		if isAlreadyStoppedError(stopErr) {
			stopErr = nil
		}
	default:
		stopErr = fmt.Errorf("HcsShutdownComputeSystem: %w", shutdownErr)
	}

	if stopErr != nil {
		termErr := terminateFn()
		switch {
		case isAlreadyStoppedError(termErr):
			stopErr = nil
		case termErr == nil || errors.Is(termErr, errVmcomputeOperationPending):
			waitErr := tracker.waitFor(ctx, notificationSystemExited)
			if waitErr == nil || isAlreadyStoppedError(waitErr) {
				stopErr = nil
			} else {
				stopErr = errors.Join(stopErr, fmt.Errorf("wait for compute system termination: %w", waitErr))
			}
		default:
			stopErr = errors.Join(stopErr, fmt.Errorf("HcsTerminateComputeSystem: %w", termErr))
		}
	}

	closeErr := closeFn()
	if stopErr != nil && closeErr != nil {
		return errors.Join(stopErr, closeErr)
	}
	if stopErr != nil {
		return stopErr
	}
	return closeErr
}
