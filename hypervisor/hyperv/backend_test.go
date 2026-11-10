// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package hyperv

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/go-microvm/hypervisor"
)

func TestBackend_Name(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "hyperv", NewBackend().Name())
}

func TestBackend_PrepareRootFS(t *testing.T) {
	t.Parallel()

	rootfsPath := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(rootfsPath, "hello.txt"), []byte("hello"), 0o644))

	initCfg := hypervisor.InitConfig{
		Cmd:        []string{"/bin/sh", "-c", "echo hello"},
		Env:        []string{"PATH=/usr/bin", "FOO=bar"},
		WorkingDir: "/app",
	}

	preparedPath, err := NewBackend().PrepareRootFS(t.Context(), rootfsPath, initCfg)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(rootfsPath, "rootfs.vhd"), preparedPath)

	configData, err := os.ReadFile(filepath.Join(rootfsPath, ".krun_config.json"))
	require.NoError(t, err)
	var config struct {
		Cmd        []string `json:"Cmd"`
		Env        []string `json:"Env"`
		WorkingDir string   `json:"WorkingDir"`
	}
	require.NoError(t, json.Unmarshal(configData, &config))
	assert.Equal(t, initCfg.Cmd, config.Cmd)
	assert.Equal(t, initCfg.Env, config.Env)
	assert.Equal(t, initCfg.WorkingDir, config.WorkingDir)

	_, err = tar2ext4.ReadExt4SuperBlock(preparedPath)
	require.NoError(t, err)

	vhd, err := os.Open(preparedPath)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, vhd.Close()) })
	_, err = vhd.Seek(-512, 2)
	require.NoError(t, err)
	cookie := make([]byte, 8)
	_, err = vhd.Read(cookie)
	require.NoError(t, err)
	assert.Equal(t, "conectix", string(cookie))

	diskType := make([]byte, 4)
	_, err = vhd.ReadAt(diskType, mustFileSize(t, vhd)-512+60)
	require.NoError(t, err)
	assert.Equal(t, uint32(2), binary.BigEndian.Uint32(diskType))
}

func TestBuildComputeSystemDoc(t *testing.T) {
	t.Parallel()

	cfg := hypervisor.VMConfig{
		Name:       "test-vm",
		RootFSPath: `C:\vm\rootfs.vhd`,
		NumVCPUs:   4,
		RAMMiB:     2048,
		Disks: []hypervisor.Disk{
			{HostPath: `C:\vm\data.vhd`, ReadOnly: false},
			{HostPath: `C:\vm\seed.vhd`, ReadOnly: true},
		},
		FilesystemMounts: []hypervisor.FilesystemMount{
			{Tag: "workspace", HostPath: `C:\src`},
			{Tag: "readonly", HostPath: `C:\data`, ReadOnly: true},
		},
		NetEndpoint: hypervisor.NetEndpoint{
			Type: hypervisor.NetEndpointHVSocket,
			Path: "network",
		},
		VsockPorts: []hypervisor.VsockPort{
			{Port: 1024, SocketPath: `\\.\pipe\agent`},
			{Port: 1025, SocketPath: `\\.\pipe\io`},
		},
	}

	doc, err := BuildComputeSystemDoc(cfg, `/runtime/vmlinux`, `/runtime/initrd.img`)
	require.NoError(t, err)

	assert.Equal(t, SchemaVersion{Major: 2, Minor: 1}, doc.SchemaVersion)
	assert.Equal(t, "go-microvm", doc.Owner)
	assert.True(t, doc.ShouldTerminateOnLastHandleClosed)
	require.NotNil(t, doc.VirtualMachine)
	assert.True(t, doc.VirtualMachine.StopOnReset)
	assert.Equal(t, uint32(4), doc.VirtualMachine.ComputeTopology.Processor.Count)
	assert.Equal(t, uint64(2048), doc.VirtualMachine.ComputeTopology.Memory.SizeInMB)
	assert.Equal(t, "test-vm", doc.VirtualMachine.GuestOs.HostName)

	attachments := doc.VirtualMachine.Devices.Scsi["0"].Attachments
	assert.Equal(t, ScsiAttachment{Path: cfg.RootFSPath, Type: "VirtualDisk"}, attachments["0"])
	assert.Equal(t, ScsiAttachment{Path: cfg.Disks[0].HostPath, Type: "VirtualDisk"}, attachments["1"])
	assert.Equal(t, ScsiAttachment{Path: cfg.Disks[1].HostPath, Type: "VirtualDisk", ReadOnly: true}, attachments["2"])

	require.Len(t, doc.VirtualMachine.Devices.Plan9.Shares, 2)
	assert.Equal(t, Plan9Share{Name: "workspace", AccessName: "workspace", Path: `C:\src`, Port: 564}, doc.VirtualMachine.Devices.Plan9.Shares[0])
	assert.Equal(t, Plan9Share{Name: "readonly", AccessName: "readonly", Path: `C:\data`, Port: 564, Flags: 1}, doc.VirtualMachine.Devices.Plan9.Shares[1])

	serviceTable := doc.VirtualMachine.Devices.HvSocket.HvSocketConfig.ServiceTable
	assert.Contains(t, serviceTable, VsockPortToServiceGUID(DefaultNetVsockPort))
	assert.Contains(t, serviceTable, VsockPortToServiceGUID(1024))
	assert.Contains(t, serviceTable, VsockPortToServiceGUID(1025))
	assert.Equal(t, "initrd=/initrd.img root=/dev/sda rw console=ttyS0 panic=-1", doc.VirtualMachine.Chipset.LinuxKernelDirect.KernelCmdLine)
	assert.Equal(t, `/runtime/vmlinux`, doc.VirtualMachine.Chipset.LinuxKernelDirect.KernelFilePath)
	assert.Equal(t, `/runtime/initrd.img`, doc.VirtualMachine.Chipset.LinuxKernelDirect.InitRdPath)
}

func TestBuildComputeSystemDoc_Defaults(t *testing.T) {
	t.Parallel()

	doc, err := BuildComputeSystemDoc(hypervisor.VMConfig{RootFSPath: "rootfs.vhd"}, "vmlinux", "")
	require.NoError(t, err)
	assert.Equal(t, uint32(1), doc.VirtualMachine.ComputeTopology.Processor.Count)
	assert.Equal(t, uint64(512), doc.VirtualMachine.ComputeTopology.Memory.SizeInMB)
	assert.Equal(t, LinuxBootDefaultCmdLine, doc.VirtualMachine.Chipset.LinuxKernelDirect.KernelCmdLine)
	assert.Nil(t, doc.VirtualMachine.Devices.Plan9)
	assert.Nil(t, doc.VirtualMachine.Devices.HvSocket)
}

func TestBackend_StartAndLifecycle(t *testing.T) {
	t.Parallel()

	handle := &mockHandle{id: "vm-id", alive: true}
	runner := &mockRunner{handle: handle}
	backend := NewBackend(
		WithKernelPath("vmlinux"),
		WithInitrdPath("initrd.img"),
		WithRunner(runner),
	)

	vmHandle, err := backend.Start(t.Context(), hypervisor.VMConfig{Name: "test-vm", RootFSPath: "rootfs.vhd"})
	require.NoError(t, err)
	require.NotNil(t, vmHandle)
	assert.Equal(t, "test-vm", runner.id)
	assert.Equal(t, "vmlinux", runner.doc.VirtualMachine.Chipset.LinuxKernelDirect.KernelFilePath)
	assert.Equal(t, "initrd.img", runner.doc.VirtualMachine.Chipset.LinuxKernelDirect.InitRdPath)
	assert.Equal(t, "vm-id", vmHandle.ID())
	assert.True(t, vmHandle.IsAlive())
	require.NoError(t, vmHandle.Stop(t.Context()))
	assert.False(t, vmHandle.IsAlive())
	assert.True(t, handle.stopped)
}

func TestBackend_StartErrors(t *testing.T) {
	t.Parallel()

	t.Run("runner failure", func(t *testing.T) {
		t.Parallel()
		backend := NewBackend(
			WithKernelPath("vmlinux"),
			WithRunner(&mockRunner{err: errors.New("create failed")}),
		)

		handle, err := backend.Start(t.Context(), hypervisor.VMConfig{Name: "test-vm", RootFSPath: "rootfs.vhd"})
		require.Error(t, err)
		assert.Nil(t, handle)
		assert.ErrorContains(t, err, "create and start compute system")
		assert.ErrorContains(t, err, "create failed")
	})

	t.Run("runtime conflicts with kernel path", func(t *testing.T) {
		t.Parallel()
		backend := NewBackend(
			WithKernelPath("vmlinux"),
			WithRuntime(&mockSource{dir: t.TempDir()}),
			WithRunner(&mockRunner{handle: &mockHandle{}}),
		)

		handle, err := backend.Start(t.Context(), hypervisor.VMConfig{Name: "test-vm"})
		require.Error(t, err)
		assert.Nil(t, handle)
		assert.ErrorContains(t, err, "mutually exclusive")
	})
}

func TestBackend_StartWithRuntime(t *testing.T) {
	t.Parallel()

	runtimeDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(runtimeDir, "vmlinux"), []byte("kernel"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(runtimeDir, "initrd.img"), []byte("initrd"), 0o644))

	source := &mockSource{dir: runtimeDir}
	runner := &mockRunner{handle: &mockHandle{id: "vm", alive: true}}
	backend := NewBackend(
		WithRuntime(source),
		WithCacheDir("cache"),
		WithRunner(runner),
	)

	_, err := backend.Start(t.Context(), hypervisor.VMConfig{Name: "test-vm", RootFSPath: "rootfs.vhd"})
	require.NoError(t, err)
	assert.Equal(t, "cache", source.cacheDir)
	assert.Equal(t, filepath.Join(runtimeDir, "vmlinux"), runner.doc.VirtualMachine.Chipset.LinuxKernelDirect.KernelFilePath)
	assert.Equal(t, filepath.Join(runtimeDir, "initrd.img"), runner.doc.VirtualMachine.Chipset.LinuxKernelDirect.InitRdPath)
}

type mockRunner struct {
	handle Handle
	err    error
	id     string
	doc    *ComputeSystem
}

func (r *mockRunner) CreateAndStart(_ context.Context, id string, doc *ComputeSystem) (Handle, error) {
	r.id = id
	r.doc = doc
	return r.handle, r.err
}

type mockHandle struct {
	id      string
	alive   bool
	stopped bool
}

func (h *mockHandle) Stop(_ context.Context) error {
	h.stopped = true
	h.alive = false
	return nil
}

func (h *mockHandle) IsAlive() bool { return h.alive }
func (h *mockHandle) ID() string    { return h.id }

type mockSource struct {
	dir      string
	err      error
	cacheDir string
}

func (s *mockSource) Ensure(_ context.Context, cacheDir string) (string, error) {
	s.cacheDir = cacheDir
	return s.dir, s.err
}

func mustFileSize(t *testing.T, file *os.File) int64 {
	t.Helper()
	info, err := file.Stat()
	require.NoError(t, err)
	return info.Size()
}
