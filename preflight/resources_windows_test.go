// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package preflight

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWindowsCheckDiskSpace(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		freeBytes uint64
		diskErr   error
		want      string
	}{
		{name: "sufficient", freeBytes: 4 * 1024 * 1024 * 1024},
		{name: "insufficient", freeBytes: 512 * 1024 * 1024, want: "insufficient disk space"},
		{name: "query error", diskErr: errors.New("query failed"), want: "cannot check disk space"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			checker := &resourceChecker{
				getDiskFreeSpace: func(_ string) (uint64, error) { return test.freeBytes, test.diskErr },
			}
			err := checker.checkDiskSpace(t.TempDir(), 2.0)
			if test.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, test.want)
		})
	}
}

func TestWindowsCheckResources(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cpus        int
		memoryBytes uint64
		memoryErr   error
		want        string
	}{
		{name: "sufficient", cpus: 4, memoryBytes: 8 * 1024 * 1024 * 1024},
		{name: "insufficient CPUs", cpus: 1, memoryBytes: 8 * 1024 * 1024 * 1024, want: "CPU cores"},
		{name: "insufficient memory", cpus: 4, memoryBytes: 512 * 1024 * 1024, want: "total memory"},
		{name: "memory query error", cpus: 4, memoryErr: errors.New("query failed"), want: "cannot check system memory"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			checker := &resourceChecker{
				numCPU:         func() int { return test.cpus },
				getTotalMemory: func() (uint64, error) { return test.memoryBytes, test.memoryErr },
			}
			err := checker.checkResources(2, 1.0)
			if test.want == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, test.want)
		})
	}
}

func TestWindowsResourceChecks(t *testing.T) {
	t.Parallel()

	disk := DiskSpaceCheck("", 2.0)
	assert.Equal(t, "disk-space", disk.Name)
	assert.False(t, disk.Required)

	resources := ResourceCheck(1, 1.0)
	assert.Equal(t, "resources", resources.Name)
	assert.False(t, resources.Required)
}
