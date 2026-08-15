// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build (linux || darwin) && cgo

package main

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type recordingVirtioFSMounter struct {
	legacyCalls []VirtioFSMount
	v3Calls     []virtioFS3Call
	v3Err       error
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
