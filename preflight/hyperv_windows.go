// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package preflight

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows"
)

type hypervChecker struct {
	loadDLL  func() error
	findProc func() error
}

func newHyperVChecker() *hypervChecker {
	dll := windows.NewLazySystemDLL("vmcompute.dll")
	proc := dll.NewProc("HcsEnumerateComputeSystems")
	return &hypervChecker{
		loadDLL:  dll.Load,
		findProc: proc.Find,
	}
}

func registerPlatformChecks(c *checker) {
	c.Register(HypervisorCheck())
	c.Register(DiskSpaceCheck("", 2.0))
	c.Register(ResourceCheck(1, 1.0))
}

// HypervisorCheck returns the required Hyper-V Host Compute Service check.
func HypervisorCheck() Check {
	hyperv := newHyperVChecker()
	return Check{
		Name:        "hyperv",
		Description: "Verify Hyper-V Host Compute Service (vmcompute) is available",
		Run:         hyperv.check,
		Required:    true,
	}
}

func (h *hypervChecker) check(_ context.Context) error {
	if err := h.loadDLL(); err != nil {
		return fmt.Errorf("load vmcompute.dll: %w", err)
	}
	if err := h.findProc(); err != nil {
		return fmt.Errorf("find HcsEnumerateComputeSystems in vmcompute.dll: %w", err)
	}
	return nil
}
