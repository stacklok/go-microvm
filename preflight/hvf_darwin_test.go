// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package preflight

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckHVF_Supported(t *testing.T) {
	t.Parallel()

	h := &hvfChecker{
		sysctlUint32: func(_ string) (uint32, error) {
			return 1, nil
		},
	}

	err := h.check(context.Background())
	assert.NoError(t, err)
}

func TestCheckHVF_NotSupported(t *testing.T) {
	t.Parallel()

	h := &hvfChecker{
		sysctlUint32: func(_ string) (uint32, error) {
			return 0, nil
		},
	}

	err := h.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not available")
	assert.Contains(t, err.Error(), "kern.hv_support=0")
}

func TestCheckHVF_SysctlError(t *testing.T) {
	t.Parallel()

	h := &hvfChecker{
		sysctlUint32: func(_ string) (uint32, error) {
			return 0, fmt.Errorf("sysctl failed")
		},
	}

	err := h.check(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot check Hypervisor.framework")
}

func TestRegisterPlatformChecks_Darwin(t *testing.T) {
	t.Parallel()

	c := &checker{}
	registerPlatformChecks(c)

	// Should register hvf + disk-space + resources = 3 checks.
	assert.Len(t, c.checks, 3)
	assert.Equal(t, "hvf", c.checks[0].Name)
	assert.True(t, c.checks[0].Required)
	assert.Equal(t, "disk-space", c.checks[1].Name)
	assert.False(t, c.checks[1].Required)
	assert.Equal(t, "resources", c.checks[2].Name)
	assert.False(t, c.checks[2].Required)
}
