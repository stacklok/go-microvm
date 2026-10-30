// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build (linux || darwin) && cgo

package main

import (
	"encoding/json"
	"errors"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stacklok/go-microvm/krun"
)

type recordingVirtioFSMounter struct {
	legacyCalls []VirtioFSMount
	v3Calls     []virtioFS3Call
	v3Err       error
	v4Calls     []virtioFS4Call
}

type virtioFS4Call struct {
	mount     VirtioFSMount
	shmSize   uint64
	semantics krun.FSSemantics
}

type virtioFS3Call struct {
	mount   VirtioFSMount
	shmSize uint64
}

func (r *recordingVirtioFSMounter) AddVirtioFS(tag, path string) error {
	r.legacyCalls = append(r.legacyCalls, VirtioFSMount{Tag: tag, Path: path})
	return nil
}

func (r *recordingVirtioFSMounter) AddVirtioFS3(tag, path string, shmSize uint64, readOnly bool) error {
	r.v3Calls = append(r.v3Calls, virtioFS3Call{
		mount:   VirtioFSMount{Tag: tag, Path: path, ReadOnly: readOnly},
		shmSize: shmSize,
	})
	return r.v3Err
}

func (r *recordingVirtioFSMounter) AddVirtioFS4(tag, path string, shmSize uint64, readOnly bool, semantics krun.FSSemantics) error {
	r.v4Calls = append(r.v4Calls, virtioFS4Call{
		mount:     VirtioFSMount{Tag: tag, Path: path, ReadOnly: readOnly},
		shmSize:   shmSize,
		semantics: semantics,
	})
	return nil
}

func TestSimplifiedOwnershipSelectsVirtioFS4(t *testing.T) {
	t.Parallel()

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(`{
		"root_path":"/rootfs",
		"num_vcpus":1,
		"ram_mib":512,
		"virtiofs_mounts":[
			{"tag":"rw","path":"/host/rw","simplified_ownership":true},
			{"tag":"ro","path":"/host/ro","read_only":true,"simplified_ownership":true}
		]
	}`), &cfg))

	recorder := &recordingVirtioFSMounter{}
	if runtime.GOOS != "darwin" {
		for _, mount := range cfg.VirtioFSMounts {
			require.ErrorContains(t, addVirtioFSMount(recorder, mount), "only supported on macOS")
		}
		require.Empty(t, recorder.v4Calls)
		return
	}
	for _, mount := range cfg.VirtioFSMounts {
		require.NoError(t, addVirtioFSMount(recorder, mount))
	}

	require.Empty(t, recorder.legacyCalls)
	require.Empty(t, recorder.v3Calls)
	require.Equal(t, []virtioFS4Call{
		{mount: VirtioFSMount{Tag: "rw", Path: "/host/rw"}, semantics: krun.FSSemanticsLinuxSimplified},
		{mount: VirtioFSMount{Tag: "ro", Path: "/host/ro", ReadOnly: true}, semantics: krun.FSSemanticsLinuxSimplified},
	}, recorder.v4Calls)
}

func TestVirtioFSMountJSONSelectsHostEnforcement(t *testing.T) {
	t.Parallel()

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(`{
		"root_path":"/rootfs",
		"num_vcpus":1,
		"ram_mib":512,
		"virtiofs_mounts":[
			{"tag":"rw","path":"/host/rw"},
			{"tag":"ro","path":"/host/ro","read_only":true}
		]
	}`), &cfg))
	require.Len(t, cfg.VirtioFSMounts, 2)

	recorder := &recordingVirtioFSMounter{}
	for _, mount := range cfg.VirtioFSMounts {
		require.NoError(t, addVirtioFSMount(recorder, mount))
	}

	require.Equal(t, []VirtioFSMount{{Tag: "rw", Path: "/host/rw"}}, recorder.legacyCalls)
	require.Equal(t, []virtioFS3Call{{
		mount:   VirtioFSMount{Tag: "ro", Path: "/host/ro", ReadOnly: true},
		shmSize: 0,
	}}, recorder.v3Calls)
}

func TestReadOnlyVirtioFSMountDoesNotDowngrade(t *testing.T) {
	t.Parallel()

	apiErr := errors.New("krun_add_virtiofs3 incompatible")
	recorder := &recordingVirtioFSMounter{v3Err: apiErr}

	err := addVirtioFSMount(recorder, VirtioFSMount{Tag: "ro", Path: "/host/ro", ReadOnly: true})
	require.ErrorIs(t, err, apiErr)
	require.Empty(t, recorder.legacyCalls)
	require.Len(t, recorder.v3Calls, 1)
}
