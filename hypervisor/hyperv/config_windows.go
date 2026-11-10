// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hyperv

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/stacklok/go-microvm/hypervisor"
)

func writeKrunConfig(rootfsPath string, initCfg hypervisor.InitConfig) error {
	data, err := json.MarshalIndent(struct {
		Cmd        []string `json:"Cmd"`
		Env        []string `json:"Env"`
		WorkingDir string   `json:"WorkingDir"`
	}{
		Cmd:        initCfg.Cmd,
		Env:        initCfg.Env,
		WorkingDir: initCfg.WorkingDir,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal krun config: %w", err)
	}
	destination := filepath.Join(rootfsPath, ".krun_config.json")
	if err := os.WriteFile(destination, data, 0o644); err != nil {
		return fmt.Errorf("write krun config to %s: %w", destination, err)
	}
	return nil
}
