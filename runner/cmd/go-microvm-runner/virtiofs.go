// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build (linux || darwin) && cgo

package main

import (
	"fmt"
	"runtime"

	"github.com/stacklok/go-microvm/krun"
)

type virtioFSMounter interface {
	AddVirtioFS(tag, path string) error
	AddVirtioFS3(tag, path string, shmSize uint64, readOnly bool) error
	AddVirtioFS4(tag, path string, shmSize uint64, readOnly bool, semantics krun.FSSemantics) error
}

func addVirtioFSMount(ctx virtioFSMounter, mount VirtioFSMount) error {
	if mount.SimplifiedOwnership {
		// libkrun's Linux passthrough backend ignores the semantics argument.
		if runtime.GOOS != "darwin" {
			return fmt.Errorf("virtiofs mount %q: simplified ownership is only supported on macOS hosts", mount.Tag)
		}
		return ctx.AddVirtioFS4(mount.Tag, mount.Path, 0, mount.ReadOnly, krun.FSSemanticsLinuxSimplified)
	}
	if mount.ReadOnly {
		return ctx.AddVirtioFS3(mount.Tag, mount.Path, 0, true)
	}
	return ctx.AddVirtioFS(mount.Tag, mount.Path)
}
