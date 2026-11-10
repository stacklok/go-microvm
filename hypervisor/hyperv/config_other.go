// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hyperv

import (
	"github.com/stacklok/go-microvm/hypervisor"
	"github.com/stacklok/go-microvm/image"
)

func writeKrunConfig(rootfsPath string, initCfg hypervisor.InitConfig) error {
	return (image.KrunConfig{
		Cmd:        initCfg.Cmd,
		Env:        initCfg.Env,
		WorkingDir: initCfg.WorkingDir,
	}).WriteTo(rootfsPath)
}
