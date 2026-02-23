// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build (linux || darwin) && cgo

package krun

/*
#cgo linux pkg-config: libkrun
#cgo linux LDFLAGS: -lkrun
#cgo darwin LDFLAGS: -lkrun -L/opt/homebrew/lib -L/usr/local/lib
#cgo darwin CFLAGS: -I${SRCDIR} -I/opt/homebrew/include -I/usr/local/include

#include <stdlib.h>
#include <errno.h>
#include "libkrun.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// LogLevel represents libkrun log levels.
type LogLevel uint32

const (
	// LogLevelOff disables logging.
	LogLevelOff LogLevel = C.KRUN_LOG_LEVEL_OFF
	// LogLevelError enables error logging.
	LogLevelError LogLevel = C.KRUN_LOG_LEVEL_ERROR
	// LogLevelWarn enables warning logging.
	LogLevelWarn LogLevel = C.KRUN_LOG_LEVEL_WARN
	// LogLevelInfo enables info logging.
	LogLevelInfo LogLevel = C.KRUN_LOG_LEVEL_INFO
	// LogLevelDebug enables debug logging.
	LogLevelDebug LogLevel = C.KRUN_LOG_LEVEL_DEBUG
	// LogLevelTrace enables trace logging.
	LogLevelTrace LogLevel = C.KRUN_LOG_LEVEL_TRACE
)

// DiskFormat represents disk image formats.
type DiskFormat uint32

const (
	// DiskFormatRaw is a raw disk image.
	DiskFormatRaw DiskFormat = C.KRUN_DISK_FORMAT_RAW
	// DiskFormatQCOW2 is a QCOW2 disk image.
	DiskFormatQCOW2 DiskFormat = C.KRUN_DISK_FORMAT_QCOW2
)

// CompatNetFeatures is the default set of virtio-net features for compatibility.
// Matches KRUN_COMPAT_NET_FEATURES from libkrun.h (defined as pure Go to avoid CGO macro issues).
const CompatNetFeatures uint32 = (1 << 0) | (1 << 1) | (1 << 7) | (1 << 10) | (1 << 11) | (1 << 14)

// Context represents a libkrun configuration context.
type Context struct {
	id C.uint32_t
}

// SetLogLevel sets the global log level for libkrun.
func SetLogLevel(level LogLevel) error {
	ret := C.krun_set_log_level(C.uint32_t(level))
	if ret < 0 {
		return fmt.Errorf("krun_set_log_level failed: %d", ret)
	}
	return nil
}

// CreateContext creates a new libkrun configuration context.
func CreateContext() (*Context, error) {
	id := C.krun_create_ctx()
	if id < 0 {
		return nil, fmt.Errorf("krun_create_ctx failed: %d", id)
	}
	return &Context{id: C.uint32_t(id)}, nil
}

// Free releases the context resources.
func (c *Context) Free() error {
	ret := C.krun_free_ctx(c.id)
	if ret < 0 {
		return fmt.Errorf("krun_free_ctx failed: %d", ret)
	}
	return nil
}

// SetVMConfig sets the basic VM configuration (vCPUs and RAM).
func (c *Context) SetVMConfig(numVCPUs uint8, ramMiB uint32) error {
	ret := C.krun_set_vm_config(c.id, C.uint8_t(numVCPUs), C.uint32_t(ramMiB))
	if ret < 0 {
		return fmt.Errorf("krun_set_vm_config failed: %d", ret)
	}
	return nil
}

// SetRoot sets the path to be used as root for the microVM.
func (c *Context) SetRoot(rootPath string) error {
	cPath := C.CString(rootPath)
	defer C.free(unsafe.Pointer(cPath))

	ret := C.krun_set_root(c.id, cPath)
	if ret < 0 {
		return fmt.Errorf("krun_set_root failed: %d", ret)
	}
	return nil
}

// SetRootDisk sets the path to the root disk image (DEPRECATED, use AddDisk instead).
func (c *Context) SetRootDisk(diskPath string) error {
	cPath := C.CString(diskPath)
	defer C.free(unsafe.Pointer(cPath))

	ret := C.krun_set_root_disk(c.id, cPath)
	if ret < 0 {
		return fmt.Errorf("krun_set_root_disk failed: %d", ret)
	}
	return nil
}

// SetRootDiskRemount configures a block device to be used as root filesystem.
// This uses libkrun's init process to mount the specified device as root.
// device: the block device path visible in the guest (e.g., "/dev/vda")
// fstype: the filesystem type (e.g., "ext4")
// mountOpts: mount options (can be empty string)
func (c *Context) SetRootDiskRemount(device, fstype, mountOpts string) error {
	cDevice := C.CString(device)
	defer C.free(unsafe.Pointer(cDevice))

	cFstype := C.CString(fstype)
	defer C.free(unsafe.Pointer(cFstype))

	cMountOpts := C.CString(mountOpts)
	defer C.free(unsafe.Pointer(cMountOpts))

	ret := C.krun_set_root_disk_remount(c.id, cDevice, cFstype, cMountOpts)
	if ret < 0 {
		return fmt.Errorf("krun_set_root_disk_remount failed: %d", ret)
	}
	return nil
}

// AddDisk adds a disk image to the VM (raw format only).
func (c *Context) AddDisk(blockID, diskPath string, readOnly bool) error {
	cBlockID := C.CString(blockID)
	defer C.free(unsafe.Pointer(cBlockID))

	cDiskPath := C.CString(diskPath)
	defer C.free(unsafe.Pointer(cDiskPath))

	ret := C.krun_add_disk(c.id, cBlockID, cDiskPath, C.bool(readOnly))
	if ret < 0 {
		return fmt.Errorf("krun_add_disk failed: %d", ret)
	}
	return nil
}

// AddDisk2 adds a disk image to the VM with format specification.
func (c *Context) AddDisk2(blockID, diskPath string, format DiskFormat, readOnly bool) error {
	cBlockID := C.CString(blockID)
	defer C.free(unsafe.Pointer(cBlockID))

	cDiskPath := C.CString(diskPath)
	defer C.free(unsafe.Pointer(cDiskPath))

	ret := C.krun_add_disk2(c.id, cBlockID, cDiskPath, C.uint32_t(format), C.bool(readOnly))
	if ret < 0 {
		return fmt.Errorf("krun_add_disk2 failed: %d", ret)
	}
	return nil
}

// AddVirtioFS adds a virtio-fs device pointing to a host directory.
func (c *Context) AddVirtioFS(tag, path string) error {
	cTag := C.CString(tag)
	defer C.free(unsafe.Pointer(cTag))

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	ret := C.krun_add_virtiofs(c.id, cTag, cPath)
	if ret < 0 {
		return fmt.Errorf("krun_add_virtiofs failed: %d", ret)
	}
	return nil
}

// SetPortMap configures port mappings for the microVM.
// Each port mapping should be in "host_port:guest_port" format.
func (c *Context) SetPortMap(ports []string) error {
	if len(ports) == 0 {
		// Passing NULL enables automatic port forwarding for all listening ports
		ret := C.krun_set_port_map(c.id, nil)
		if ret < 0 {
			return fmt.Errorf("krun_set_port_map failed: %d", ret)
		}
		return nil
	}

	// Create C string array (NULL-terminated)
	cPorts := make([]*C.char, len(ports)+1)
	for i, p := range ports {
		cPorts[i] = C.CString(p)
	}
	cPorts[len(ports)] = nil // NULL terminator

	// Cleanup C strings after call
	defer func() {
		for _, cp := range cPorts[:len(ports)] {
			C.free(unsafe.Pointer(cp))
		}
	}()

	ret := C.krun_set_port_map(c.id, &cPorts[0])
	if ret < 0 {
		return fmt.Errorf("krun_set_port_map failed: %d", ret)
	}
	return nil
}

// SetConsoleOutput configures the console to write to a file.
func (c *Context) SetConsoleOutput(filepath string) error {
	cPath := C.CString(filepath)
	defer C.free(unsafe.Pointer(cPath))

	ret := C.krun_set_console_output(c.id, cPath)
	if ret < 0 {
		return fmt.Errorf("krun_set_console_output failed: %d", ret)
	}
	return nil
}

// SetExec sets the executable to be run inside the microVM.
// execPath: Path to the executable (relative to configured root).
// argv: Arguments (argv[0] is typically the program name).
// envp: Environment variables.
func (c *Context) SetExec(execPath string, argv []string, envp []string) error {
	cExecPath := C.CString(execPath)
	defer C.free(unsafe.Pointer(cExecPath))

	// Create C string array for argv (NULL-terminated)
	cArgv := make([]*C.char, len(argv)+1)
	for i, a := range argv {
		cArgv[i] = C.CString(a)
	}
	cArgv[len(argv)] = nil

	defer func() {
		for _, ca := range cArgv[:len(argv)] {
			C.free(unsafe.Pointer(ca))
		}
	}()

	// Create C string array for envp (NULL-terminated)
	var cEnvp []*C.char
	if len(envp) > 0 {
		cEnvp = make([]*C.char, len(envp)+1)
		for i, e := range envp {
			cEnvp[i] = C.CString(e)
		}
		cEnvp[len(envp)] = nil

		defer func() {
			for _, ce := range cEnvp[:len(envp)] {
				C.free(unsafe.Pointer(ce))
			}
		}()
	}

	var envpPtr **C.char
	if len(envp) > 0 {
		envpPtr = &cEnvp[0]
	}

	ret := C.krun_set_exec(c.id, cExecPath, &cArgv[0], envpPtr)
	if ret < 0 {
		return fmt.Errorf("krun_set_exec failed: %d", ret)
	}
	return nil
}

// SetEnv sets environment variables for the guest.
func (c *Context) SetEnv(envp []string) error {
	if len(envp) == 0 {
		// NULL means inherit current environment
		ret := C.krun_set_env(c.id, nil)
		if ret < 0 {
			return fmt.Errorf("krun_set_env failed: %d", ret)
		}
		return nil
	}

	// Create C string array (NULL-terminated)
	cEnvp := make([]*C.char, len(envp)+1)
	for i, e := range envp {
		cEnvp[i] = C.CString(e)
	}
	cEnvp[len(envp)] = nil // NULL terminator

	// Cleanup C strings after call
	defer func() {
		for _, ce := range cEnvp[:len(envp)] {
			C.free(unsafe.Pointer(ce))
		}
	}()

	ret := C.krun_set_env(c.id, &cEnvp[0])
	if ret < 0 {
		return fmt.Errorf("krun_set_env failed: %d", ret)
	}
	return nil
}

// StartEnter starts the microVM and enters it.
// IMPORTANT: This function NEVER returns on success. The calling process becomes
// the VM supervisor and will call exit() when the VM shuts down.
// It only returns an error if something fails before the VM can start.
func (c *Context) StartEnter() error {
	ret := C.krun_start_enter(c.id)
	// If we get here, something went wrong
	return fmt.Errorf("krun_start_enter failed: %d", ret)
}

// AddNetUnixStream adds a network device backed by a Unix stream socket.
// Used with gvproxy's QEMU transport (4-byte BE length-prefixed frames over SOCK_STREAM).
// This disables TSI networking.
func (c *Context) AddNetUnixStream(fd int, path string, mac []byte, features, flags uint32) error {
	if len(mac) == 0 {
		mac = []byte{0x02, 0x4b, 0x72, 0x75, 0x6e, 0x00} // 02:4b:72:75:6e:00 ("Krun")
	}
	macPtr := (*C.uint8_t)(unsafe.Pointer(&mac[0]))

	var cPath *C.char
	if path != "" {
		cPath = C.CString(path)
		defer C.free(unsafe.Pointer(cPath))
	}

	ret := C.krun_add_net_unixstream(c.id, cPath, C.int(fd), macPtr,
		C.uint32_t(features), C.uint32_t(flags))
	if ret < 0 {
		return fmt.Errorf("krun_add_net_unixstream failed: %d", ret)
	}
	return nil
}

// IsAvailable checks if libkrun is available and working.
func IsAvailable() bool {
	// Try to create and free a context to verify libkrun is working
	ctx, err := CreateContext()
	if err != nil {
		return false
	}
	_ = ctx.Free()
	return true
}
