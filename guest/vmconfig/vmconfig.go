// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package vmconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// configPath is the guest path where the host writes the VM config.
const configPath = "/etc/propolis-vm.json"

// Config holds settings written by the host and read by the guest init.
// Zero values mean "use the built-in default" for each field.
type Config struct {
	// TmpSizeMiB is the size of the /tmp tmpfs in MiB. Zero means use the
	// mount package default (256 MiB).
	TmpSizeMiB uint32 `json:"tmp_size_mib,omitempty"`
}

// Read loads the VM config from /etc/propolis-vm.json.
// Returns a zero-value Config (all defaults) if the file does not exist,
// ensuring backward compatibility with hosts that do not write the file.
func Read() (Config, error) {
	data, err := os.ReadFile(configPath)
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
