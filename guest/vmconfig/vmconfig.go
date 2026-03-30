// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package vmconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// GuestPath is the guest path where the host writes the VM config.
const GuestPath = "/etc/go-microvm.json"

// Config holds settings written by the host and read by the guest init.
// Zero values mean "use the built-in default" for each field.
type Config struct {
	// TmpSizeMiB is the size of the /tmp tmpfs in MiB. Zero means use the
	// mount package default (256 MiB).
	TmpSizeMiB uint32 `json:"tmp_size_mib,omitempty"`
	// VirtioFSMounts describes virtiofs mounts the host configured for the VM.
	// The guest init uses this to determine mount-time options (e.g. read-only).
	VirtioFSMounts []VirtioFSMountInfo `json:"virtiofs_mounts,omitempty"`
}

// VirtioFSMountInfo carries mount metadata from the host to the guest init.
type VirtioFSMountInfo struct {
	// Tag is the virtiofs tag identifying this mount.
	Tag string `json:"tag"`
	// ReadOnly indicates the mount should be read-only inside the guest.
	ReadOnly bool `json:"read_only,omitempty"`
}

// Read loads the VM config from /etc/go-microvm.json.
// Returns a zero-value Config (all defaults) if the file does not exist,
// ensuring backward compatibility with hosts that do not write the file.
func Read() (Config, error) {
	return readFrom(GuestPath)
}

// readFrom loads the VM config from the given path.
func readFrom(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("reading vm config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing vm config: %w", err)
	}
	return cfg, nil
}
