// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hyperv

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	errVmcomputeOperationPending syscall.Errno = 0xC0370103

	notificationSystemExited          uint32 = 0x00000001
	notificationSystemCreateCompleted uint32 = 0x00000002
	notificationSystemStartCompleted  uint32 = 0x00000003
	notificationServiceDisconnect     uint32 = 0x01000000
)

var (
	vmcomputeDLL = windows.NewLazySystemDLL("vmcompute.dll")
	ole32DLL     = windows.NewLazySystemDLL("ole32.dll")

	hcsCreateComputeSystem             = vmcomputeDLL.NewProc("HcsCreateComputeSystem")
	hcsStartComputeSystem              = vmcomputeDLL.NewProc("HcsStartComputeSystem")
	hcsShutdownComputeSystem           = vmcomputeDLL.NewProc("HcsShutdownComputeSystem")
	hcsTerminateComputeSystem          = vmcomputeDLL.NewProc("HcsTerminateComputeSystem")
	hcsGetComputeSystemProperties      = vmcomputeDLL.NewProc("HcsGetComputeSystemProperties")
	hcsCloseComputeSystem              = vmcomputeDLL.NewProc("HcsCloseComputeSystem")
	hcsRegisterComputeSystemCallback   = vmcomputeDLL.NewProc("HcsRegisterComputeSystemCallback")
	hcsUnregisterComputeSystemCallback = vmcomputeDLL.NewProc("HcsUnregisterComputeSystemCallback")
	coTaskMemFree                      = ole32DLL.NewProc("CoTaskMemFree")

	callbackAddress  = syscall.NewCallback(computeSystemCallback)
	callbackSequence atomic.Uintptr
	callbackRegistry sync.Map
)

type hcsNotification struct {
	typeID uint32
	err    error
}

type callbackState struct {
	notifications chan hcsNotification
}

type defaultRunner struct{}

func (defaultRunner) CreateAndStart(ctx context.Context, id string, doc *ComputeSystem) (Handle, error) {
	document, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal compute system document: %w", err)
	}
	idPointer, err := windows.UTF16PtrFromString(id)
	if err != nil {
		return nil, fmt.Errorf("encode compute system ID: %w", err)
	}
	documentPointer, err := windows.UTF16PtrFromString(string(document))
	if err != nil {
		return nil, fmt.Errorf("encode compute system document: %w", err)
	}

	var system windows.Handle
	var createResultPointer *uint16
	createResult, _, _ := hcsCreateComputeSystem.Call(
		uintptr(unsafe.Pointer(idPointer)),
		uintptr(unsafe.Pointer(documentPointer)),
		0,
		uintptr(unsafe.Pointer(&system)),
		uintptr(unsafe.Pointer(&createResultPointer)),
	)
	createResultText := takeResultString(createResultPointer)
	createErr := hresultError(createResult)
	if createErr != nil && createResultText != "" {
		createErr = fmt.Errorf("%w: %s", createErr, createResultText)
	}
	if createErr != nil && !errors.Is(createErr, errVmcomputeOperationPending) {
		return nil, fmt.Errorf("HcsCreateComputeSystem: %w", createErr)
	}

	handle := &vmcomputeHandle{id: id, system: system}
	if err := handle.registerCallback(); err != nil {
		_ = terminateSystem(system)
		_ = closeSystem(system)
		return nil, fmt.Errorf("register compute system callback: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = handle.close()
		}
	}()

	if errors.Is(createErr, errVmcomputeOperationPending) {
		if err := handle.waitFor(ctx, notificationSystemCreateCompleted); err != nil {
			_ = terminateSystem(system)
			return nil, fmt.Errorf("wait for compute system creation: %w", err)
		}
	}

	startErr := callWithResult(hcsStartComputeSystem, uintptr(system))
	if startErr != nil && !errors.Is(startErr, errVmcomputeOperationPending) {
		_ = terminateSystem(system)
		return nil, fmt.Errorf("HcsStartComputeSystem: %w", startErr)
	}
	if errors.Is(startErr, errVmcomputeOperationPending) {
		if err := handle.waitFor(ctx, notificationSystemStartCompleted); err != nil {
			_ = terminateSystem(system)
			return nil, fmt.Errorf("wait for compute system start: %w", err)
		}
	}

	cleanup = false
	return handle, nil
}

type vmcomputeHandle struct {
	mu              sync.Mutex
	id              string
	system          windows.Handle
	callbackHandle  windows.Handle
	callbackContext uintptr
	callbackState   *callbackState
}

func (handle *vmcomputeHandle) Stop(ctx context.Context) error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.system == 0 {
		return nil
	}

	shutdownErr := callWithResult(hcsShutdownComputeSystem, uintptr(handle.system))
	if shutdownErr == nil || errors.Is(shutdownErr, errVmcomputeOperationPending) {
		shutdownErr = handle.waitFor(ctx, notificationSystemExited)
	}
	if shutdownErr != nil {
		if err := terminateSystem(handle.system); err != nil && !errors.Is(err, errVmcomputeOperationPending) {
			shutdownErr = errors.Join(shutdownErr, fmt.Errorf("HcsTerminateComputeSystem: %w", err))
		}
	}
	closeErr := handle.closeLocked()
	if shutdownErr != nil {
		if closeErr != nil {
			return errors.Join(shutdownErr, closeErr)
		}
		return shutdownErr
	}
	return closeErr
}

func (handle *vmcomputeHandle) IsAlive() bool {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.system == 0 {
		return false
	}

	queryPointer, err := windows.UTF16PtrFromString("{}")
	if err != nil {
		return false
	}
	var propertiesPointer *uint16
	var resultPointer *uint16
	result, _, _ := hcsGetComputeSystemProperties.Call(
		uintptr(handle.system),
		uintptr(unsafe.Pointer(queryPointer)),
		uintptr(unsafe.Pointer(&propertiesPointer)),
		uintptr(unsafe.Pointer(&resultPointer)),
	)
	freeResultString(resultPointer)
	if err := hresultError(result); err != nil {
		freeResultString(propertiesPointer)
		return false
	}
	propertiesJSON := takeResultString(propertiesPointer)
	var properties struct {
		State   string `json:"State"`
		Stopped bool   `json:"Stopped"`
	}
	if err := json.Unmarshal([]byte(propertiesJSON), &properties); err != nil {
		return false
	}
	if properties.Stopped {
		return false
	}
	state := strings.ToLower(properties.State)
	return state != "" && state != "stopped" && state != "exited"
}

func (handle *vmcomputeHandle) ID() string { return handle.id }

func (handle *vmcomputeHandle) registerCallback() error {
	state := &callbackState{notifications: make(chan hcsNotification, 8)}
	contextID := callbackSequence.Add(1)
	callbackRegistry.Store(contextID, state)

	var callbackHandle windows.Handle
	result, _, _ := hcsRegisterComputeSystemCallback.Call(
		uintptr(handle.system),
		callbackAddress,
		contextID,
		uintptr(unsafe.Pointer(&callbackHandle)),
	)
	if err := hresultError(result); err != nil {
		callbackRegistry.Delete(contextID)
		return fmt.Errorf("HcsRegisterComputeSystemCallback: %w", err)
	}
	handle.callbackHandle = callbackHandle
	handle.callbackContext = contextID
	handle.callbackState = state
	return nil
}

func (handle *vmcomputeHandle) waitFor(ctx context.Context, expected uint32) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case notification := <-handle.callbackState.notifications:
			if notification.typeID == notificationServiceDisconnect {
				return fmt.Errorf("vmcompute service disconnected")
			}
			if notification.typeID == notificationSystemExited && expected != notificationSystemExited {
				if notification.err != nil {
					return notification.err
				}
				return fmt.Errorf("compute system exited before operation completed")
			}
			if notification.typeID == expected {
				return notification.err
			}
		}
	}
}

func (handle *vmcomputeHandle) close() error {
	handle.mu.Lock()
	defer handle.mu.Unlock()
	return handle.closeLocked()
}

func (handle *vmcomputeHandle) closeLocked() error {
	var unregisterErr error
	if handle.callbackHandle != 0 {
		result, _, _ := hcsUnregisterComputeSystemCallback.Call(uintptr(handle.callbackHandle))
		if err := hresultError(result); err != nil {
			unregisterErr = fmt.Errorf("HcsUnregisterComputeSystemCallback: %w", err)
		}
		callbackRegistry.Delete(handle.callbackContext)
		handle.callbackHandle = 0
	}
	closeErr := closeSystem(handle.system)
	handle.system = 0
	if unregisterErr != nil && closeErr != nil {
		return errors.Join(unregisterErr, closeErr)
	}
	if unregisterErr != nil {
		return unregisterErr
	}
	return closeErr
}

func computeSystemCallback(notificationType, contextID, status, _ uintptr) uintptr {
	value, ok := callbackRegistry.Load(contextID)
	if !ok {
		return 0
	}
	state := value.(*callbackState)
	notification := hcsNotification{typeID: uint32(notificationType), err: hresultError(status)}
	select {
	case state.notifications <- notification:
	default:
	}
	return 0
}

func callWithResult(procedure *windows.LazyProc, args ...uintptr) error {
	emptyOptions, err := windows.UTF16PtrFromString("")
	if err != nil {
		return err
	}
	var resultPointer *uint16
	callArgs := append(args, uintptr(unsafe.Pointer(emptyOptions)), uintptr(unsafe.Pointer(&resultPointer)))
	result, _, _ := procedure.Call(callArgs...)
	resultText := takeResultString(resultPointer)
	if err := hresultError(result); err != nil {
		if resultText != "" {
			return fmt.Errorf("%w: %s", err, resultText)
		}
		return err
	}
	return nil
}

func terminateSystem(system windows.Handle) error {
	return callWithResult(hcsTerminateComputeSystem, uintptr(system))
}

func closeSystem(system windows.Handle) error {
	if system == 0 {
		return nil
	}
	result, _, _ := hcsCloseComputeSystem.Call(uintptr(system))
	if err := hresultError(result); err != nil {
		return fmt.Errorf("HcsCloseComputeSystem: %w", err)
	}
	return nil
}

func hresultError(result uintptr) error {
	if int32(result) >= 0 {
		return nil
	}
	if result&0x1fff0000 == 0x00070000 {
		result &= 0xffff
	}
	return syscall.Errno(result)
}

func takeResultString(pointer *uint16) string {
	if pointer == nil {
		return ""
	}
	value := windows.UTF16PtrToString(pointer)
	freeResultString(pointer)
	return value
}

func freeResultString(pointer *uint16) {
	if pointer != nil {
		_, _, _ = coTaskMemFree.Call(uintptr(unsafe.Pointer(pointer))) //nolint:errcheck // CoTaskMemFree returns void
	}
}
