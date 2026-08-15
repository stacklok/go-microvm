// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build (linux || darwin) && cgo

package main

type virtioFSMounter interface {
	AddVirtioFS(tag, path string) error
	AddVirtioFS3(tag, path string, shmSize uint64, readOnly bool) error
}

func addVirtioFSMount(ctx virtioFSMounter, mount VirtioFSMount) error {
	if mount.ReadOnly {
		return ctx.AddVirtioFS3(mount.Tag, mount.Path, 0, true)
	}
	return ctx.AddVirtioFS(mount.Tag, mount.Path)
}
