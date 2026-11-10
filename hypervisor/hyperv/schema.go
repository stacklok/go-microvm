// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hyperv

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/stacklok/go-microvm/hypervisor"
)

const (
	// DefaultNetVsockPort is the Hyper-V socket port used by the network endpoint.
	DefaultNetVsockPort uint32 = 2048
	// LinuxBootDefaultCmdLine is the kernel command line used without an initrd.
	LinuxBootDefaultCmdLine = "root=/dev/sda rw console=ttyS0 panic=-1"

	defaultOwner            = "go-microvm"
	defaultPlan9Port  int32 = 564
	readOnlyPlan9Flag int32 = 1
)

// SchemaVersion identifies an HCS schema version.
type SchemaVersion struct {
	Major uint32 `json:"Major"`
	Minor uint32 `json:"Minor"`
}

// ComputeSystem is an HCS v2 compute-system document.
type ComputeSystem struct {
	Owner                             string          `json:"Owner,omitempty"`
	SchemaVersion                     SchemaVersion   `json:"SchemaVersion"`
	VirtualMachine                    *VirtualMachine `json:"VirtualMachine,omitempty"`
	ShouldTerminateOnLastHandleClosed bool            `json:"ShouldTerminateOnLastHandleClosed,omitempty"`
}

// VirtualMachine configures the Linux Utility VM.
type VirtualMachine struct {
	StopOnReset     bool             `json:"StopOnReset,omitempty"`
	Chipset         *Chipset         `json:"Chipset,omitempty"`
	ComputeTopology *ComputeTopology `json:"ComputeTopology,omitempty"`
	Devices         *Devices         `json:"Devices,omitempty"`
	GuestOs         *GuestOs         `json:"GuestOs,omitempty"`
}

// Chipset configures direct Linux kernel boot.
type Chipset struct {
	LinuxKernelDirect *LinuxKernelDirect `json:"LinuxKernelDirect,omitempty"`
}

// LinuxKernelDirect contains direct-boot kernel assets and arguments.
type LinuxKernelDirect struct {
	KernelFilePath string `json:"KernelFilePath,omitempty"`
	InitRdPath     string `json:"InitRdPath,omitempty"`
	KernelCmdLine  string `json:"KernelCmdLine,omitempty"`
}

// GuestOs configures guest operating-system properties.
type GuestOs struct {
	HostName string `json:"HostName,omitempty"`
}

// ComputeTopology configures VM memory and processors.
type ComputeTopology struct {
	Memory    *Memory    `json:"Memory,omitempty"`
	Processor *Processor `json:"Processor,omitempty"`
}

// Memory configures VM memory.
type Memory struct {
	SizeInMB              uint64 `json:"SizeInMB,omitempty"`
	AllowOvercommit       bool   `json:"AllowOvercommit,omitempty"`
	EnableDeferredCommit  bool   `json:"EnableDeferredCommit,omitempty"`
	EnableColdDiscardHint bool   `json:"EnableColdDiscardHint,omitempty"`
}

// Processor configures virtual processors.
type Processor struct {
	Count uint32 `json:"Count,omitempty"`
}

// Devices configures VM devices.
type Devices struct {
	Scsi     map[string]Scsi    `json:"Scsi,omitempty"`
	Plan9    *Plan9             `json:"Plan9,omitempty"`
	HvSocket *HvSocket          `json:"HvSocket,omitempty"`
	ComPorts map[string]ComPort `json:"ComPorts,omitempty"`
}

// Scsi configures one SCSI controller.
type Scsi struct {
	Attachments map[string]ScsiAttachment `json:"Attachments,omitempty"`
}

// ScsiAttachment configures a virtual disk attachment.
type ScsiAttachment struct {
	Path     string `json:"Path,omitempty"`
	Type     string `json:"Type,omitempty"`
	ReadOnly bool   `json:"ReadOnly,omitempty"`
}

// Plan9 configures host directory shares.
type Plan9 struct {
	Shares []Plan9Share `json:"Shares,omitempty"`
}

// Plan9Share configures one host directory share.
type Plan9Share struct {
	Name       string `json:"Name,omitempty"`
	AccessName string `json:"AccessName,omitempty"`
	Path       string `json:"Path,omitempty"`
	Port       int32  `json:"Port,omitempty"`
	Flags      int32  `json:"Flags,omitempty"`
}

// HvSocket configures Hyper-V socket services.
type HvSocket struct {
	HvSocketConfig *HvSocketSystemConfig `json:"HvSocketConfig,omitempty"`
}

// HvSocketSystemConfig configures system-wide Hyper-V socket access.
type HvSocketSystemConfig struct {
	DefaultBindSecurityDescriptor    string                           `json:"DefaultBindSecurityDescriptor,omitempty"`
	DefaultConnectSecurityDescriptor string                           `json:"DefaultConnectSecurityDescriptor,omitempty"`
	ServiceTable                     map[string]HvSocketServiceConfig `json:"ServiceTable,omitempty"`
}

// HvSocketServiceConfig configures one Hyper-V socket service.
type HvSocketServiceConfig struct {
	BindSecurityDescriptor    string `json:"BindSecurityDescriptor,omitempty"`
	ConnectSecurityDescriptor string `json:"ConnectSecurityDescriptor,omitempty"`
	AllowWildcardBinds        bool   `json:"AllowWildcardBinds,omitempty"`
	Disabled                  bool   `json:"Disabled,omitempty"`
}

// ComPort configures a serial port backed by a named pipe.
type ComPort struct {
	NamedPipe string `json:"NamedPipe,omitempty"`
}

// VsockPortToServiceGUID maps a Linux vsock port to the standard Hyper-V service GUID.
func VsockPortToServiceGUID(port uint32) string {
	return fmt.Sprintf("%08x-facb-11e6-bd58-64006a7986d3", port)
}

// BuildComputeSystemDoc maps a generic VM configuration to an HCS v2 document.
func BuildComputeSystemDoc(
	cfg hypervisor.VMConfig,
	kernelPath string,
	initrdPath string,
) (*ComputeSystem, error) {
	processorCount := cfg.NumVCPUs
	if processorCount == 0 {
		processorCount = 1
	}
	memorySize := uint64(cfg.RAMMiB)
	if memorySize == 0 {
		memorySize = 512
	}

	attachments := make(map[string]ScsiAttachment, len(cfg.Disks)+1)
	attachments["0"] = ScsiAttachment{Path: cfg.RootFSPath, Type: "VirtualDisk"}
	for index, disk := range cfg.Disks {
		attachments[strconv.Itoa(index+1)] = ScsiAttachment{
			Path:     disk.HostPath,
			Type:     "VirtualDisk",
			ReadOnly: disk.ReadOnly,
		}
	}

	devices := &Devices{
		Scsi: map[string]Scsi{
			"0": {Attachments: attachments},
		},
	}
	if len(cfg.FilesystemMounts) > 0 {
		shares := make([]Plan9Share, 0, len(cfg.FilesystemMounts))
		for _, mount := range cfg.FilesystemMounts {
			flags := int32(0)
			if mount.ReadOnly {
				flags = readOnlyPlan9Flag
			}
			shares = append(shares, Plan9Share{
				Name:       mount.Tag,
				AccessName: mount.Tag,
				Path:       mount.HostPath,
				Port:       defaultPlan9Port,
				Flags:      flags,
			})
		}
		devices.Plan9 = &Plan9{Shares: shares}
	}

	serviceTable := make(map[string]HvSocketServiceConfig, len(cfg.VsockPorts)+1)
	if cfg.NetEndpoint.Type == hypervisor.NetEndpointHVSocket {
		serviceTable[VsockPortToServiceGUID(DefaultNetVsockPort)] = HvSocketServiceConfig{}
	}
	for _, port := range cfg.VsockPorts {
		serviceTable[VsockPortToServiceGUID(port.Port)] = HvSocketServiceConfig{}
	}
	if len(serviceTable) > 0 {
		devices.HvSocket = &HvSocket{
			HvSocketConfig: &HvSocketSystemConfig{
				DefaultBindSecurityDescriptor:    "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
				DefaultConnectSecurityDescriptor: "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
				ServiceTable:                     serviceTable,
			},
		}
	}

	kernelCmdLine := LinuxBootDefaultCmdLine
	if initrdPath != "" {
		kernelCmdLine = "initrd=/" + filepath.Base(initrdPath) + " " + LinuxBootDefaultCmdLine
	}

	return &ComputeSystem{
		Owner:         defaultOwner,
		SchemaVersion: SchemaVersion{Major: 2, Minor: 1},
		VirtualMachine: &VirtualMachine{
			StopOnReset: true,
			Chipset: &Chipset{LinuxKernelDirect: &LinuxKernelDirect{
				KernelFilePath: kernelPath,
				InitRdPath:     initrdPath,
				KernelCmdLine:  kernelCmdLine,
			}},
			ComputeTopology: &ComputeTopology{
				Memory:    &Memory{SizeInMB: memorySize},
				Processor: &Processor{Count: processorCount},
			},
			Devices: devices,
			GuestOs: &GuestOs{HostName: cfg.Name},
		},
		ShouldTerminateOnLastHandleClosed: true,
	}, nil
}
