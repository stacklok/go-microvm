// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package image handles pulling OCI container images and extracting them
// to a rootfs directory suitable for libkrun.
package image

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// OCIConfig holds the relevant fields from an OCI image configuration.
type OCIConfig struct {
	Entrypoint []string
	Cmd        []string
	Env        []string
	WorkingDir string
	User       string
}

// KrunConfig is written to /.krun_config.json in the rootfs.
// libkrun's built-in init reads this to determine what to execute.
type KrunConfig struct {
	Cmd        []string `json:"Cmd"`
	Env        []string `json:"Env"`
	WorkingDir string   `json:"WorkingDir"`
}

// RootFS represents an extracted rootfs ready for libkrun.
type RootFS struct {
	Path   string     // Filesystem path to the extracted rootfs directory
	Config *OCIConfig // Parsed OCI image configuration
}

// krunConfigFile is the filename written inside the rootfs.
const krunConfigFile = ".krun_config.json"

// WriteTo writes the krun config as /.krun_config.json in the rootfs.
func (kc KrunConfig) WriteTo(rootfsPath string) error {
	data, err := json.MarshalIndent(kc, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal krun config: %w", err)
	}

	dst := filepath.Join(rootfsPath, krunConfigFile)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return fmt.Errorf("write krun config to %s: %w", dst, err)
	}

	return nil
}
