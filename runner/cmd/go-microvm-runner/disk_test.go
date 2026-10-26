// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build (linux || darwin) && cgo

package main

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/stacklok/go-microvm/krun"
)

func TestDiskFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		want    krun.DiskFormat
		wantErr bool
	}{
		{name: "", want: krun.DiskFormatRaw},
		{name: "raw", want: krun.DiskFormatRaw},
		{name: "qcow2", want: krun.DiskFormatQCOW2},
		{name: "vmdk", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := diskFormat(tt.name)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestDiskJSONMatchesRunnerConfig(t *testing.T) {
	t.Parallel()

	var cfg Config
	require.NoError(t, json.Unmarshal([]byte(`{"disks":[{"block_id":"data","path":"/d/data.img","format":"qcow2","read_only":true}]}`), &cfg))
	require.Equal(t, []Disk{{ID: "data", Path: "/d/data.img", Format: "qcow2", ReadOnly: true}}, cfg.Disks)
}
