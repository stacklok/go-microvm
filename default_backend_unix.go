// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package microvm

import (
	"github.com/stacklok/go-microvm/hypervisor"
	"github.com/stacklok/go-microvm/hypervisor/libkrun"
)

func defaultBackend() hypervisor.Backend {
	return libkrun.NewBackend()
}
