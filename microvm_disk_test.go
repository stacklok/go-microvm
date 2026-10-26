// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package microvm

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithDisks_AppendsInOrder(t *testing.T) {
	t.Parallel()

	cfg := defaultConfig()
	assert.Empty(t, cfg.disks)

	WithDisks(Disk{ID: "data", HostPath: "/var/lib/vm/data.img"}).apply(cfg)
	WithDisks(Disk{ID: "seed", HostPath: "/var/lib/vm/seed.qcow2", Format: DiskFormatQCOW2, ReadOnly: true}).apply(cfg)

	require.Len(t, cfg.disks, 2)
	assert.Equal(t, "data", cfg.disks[0].ID)
	assert.Equal(t, "seed", cfg.disks[1].ID)
	assert.Equal(t, DiskFormatQCOW2, cfg.disks[1].Format)
	assert.True(t, cfg.disks[1].ReadOnly)
}

func TestValidateDisks(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	image := filepath.Join(dir, "data.img")
	require.NoError(t, os.WriteFile(image, nil, 0o600))

	tests := []struct {
		name    string
		disks   []Disk
		wantErr string
	}{
		{name: "no disks"},
		{name: "raw default", disks: []Disk{{ID: "data", HostPath: image}}},
		{name: "qcow2 read-only", disks: []Disk{{ID: "seed", HostPath: image, Format: DiskFormatQCOW2, ReadOnly: true}}},
		{name: "empty ID", disks: []Disk{{HostPath: image}}, wantErr: "ID must not be empty"},
		{name: "duplicate ID", disks: []Disk{{ID: "a", HostPath: image}, {ID: "a", HostPath: image}}, wantErr: "duplicate ID"},
		{name: "unknown format", disks: []Disk{{ID: "a", HostPath: image, Format: "vmdk"}}, wantErr: "unsupported format"},
		{name: "relative path", disks: []Disk{{ID: "a", HostPath: "data.img"}}, wantErr: "must be absolute"},
		{name: "missing file", disks: []Disk{{ID: "a", HostPath: filepath.Join(dir, "missing.img")}}, wantErr: "no such file"},
		{name: "directory", disks: []Disk{{ID: "a", HostPath: dir}}, wantErr: "not a regular file"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := defaultConfig()
			WithDisks(tt.disks...).apply(cfg)
			err := validateDisks(cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestRun_RejectsInvalidDiskBeforeStart(t *testing.T) {
	t.Parallel()

	_, err := Run(context.Background(), "alpine:latest",
		WithDataDir(t.TempDir()),
		WithDisks(Disk{ID: "data", HostPath: "relative.img"}),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be absolute")
}

func TestToHypervisorDisks(t *testing.T) {
	t.Parallel()

	assert.Nil(t, toHypervisorDisks(nil))

	out := toHypervisorDisks([]Disk{
		{ID: "data", HostPath: "/d/data.img"},
		{ID: "seed", HostPath: "/d/seed.qcow2", Format: DiskFormatQCOW2, ReadOnly: true},
	})
	require.Len(t, out, 2)
	assert.Equal(t, "data", out[0].ID)
	assert.Equal(t, "/d/data.img", out[0].HostPath)
	assert.Equal(t, "raw", out[0].Format, "empty format defaults to raw")
	assert.False(t, out[0].ReadOnly)
	assert.Equal(t, "qcow2", out[1].Format)
	assert.True(t, out[1].ReadOnly)
}
